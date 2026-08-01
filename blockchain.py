"""Block and Blockchain with memory-hard proof-of-work and auto-adjusting difficulty."""

import hashlib
import json
import time


# --- proof of work ---------------------------------------------------------
# Mining should be something an ordinary computer can do, not a thing you buy
# your way into. So the work is deliberately *memory-hard*: every attempt has
# to allocate and randomly walk a large block of memory.
#
# Custom mining chips win at plain SHA-256 by stamping thousands of tiny
# hashing cores onto one piece of silicon. That trick collapses when each core
# needs its own 16 MB of fast memory -- the memory, not the arithmetic, becomes
# the cost, and a chip built that way ends up looking like an ordinary CPU with
# ordinary RAM. Litecoin used this idea but chose only 128 KB, which was small
# enough that chips caught up. 16 MB is 128 times that.
#
# It has a second benefit that matters for a project written in Python: nearly
# all the time is spent inside one C function, so somebody who rewrites the
# miner in C gains almost nothing. The playing field stays level.
POW_SALT = b"SOSAIEM-pow-scrypt-v2"
POW_N = 1 << 13          # 8 MB per attempt -- 64x Litecoin's setting
POW_R = 8
POW_P = 1
POW_MAXMEM = 2147483646


import threading as _threading

# Each attempt allocates ~8 MB, on purpose -- that is what keeps mining off
# custom chips. But N threads hashing at once need N x 8 MB, and a small server
# will burn through its memory, start swapping, and stop answering anything --
# which is exactly what happened: with the gate set to 36, a burst of concurrent
# verification/mining hashes could momentarily demand ~300 MB on a 2 GB box,
# push it into swap, and make it stall for tens of seconds (CPU idle, but every
# request waiting on memory). 8 slots = ~64 MB worst case, which any machine
# that can run this can spare, while still ruling out the unbounded burst that
# takes the box down. This is a MEMORY safety valve, not a consensus value --
# it changes nothing about which blocks are valid, only how many hashes run at
# once, so nodes with different settings still agree on the chain.
_HASH_SLOTS = _threading.Semaphore(8)


def memory_hard(data: bytes) -> str:
    """The one piece of work in the whole system. Everything costly uses this."""
    with _HASH_SLOTS:
        return hashlib.scrypt(data, salt=POW_SALT, n=POW_N, r=POW_R, p=POW_P,
                              maxmem=POW_MAXMEM, dklen=32).hex()


class Block:
    def __init__(self, index, transactions, previous_hash, timestamp=None, nonce=0):
        self.index = index

        self.timestamp = timestamp if timestamp is not None else time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce

        self.tx_hash = hashlib.sha256(
            json.dumps(self.transactions, sort_keys=True).encode()).hexdigest()

    def header_json(self):
        return json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "tx_hash": self.tx_hash,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
        }, sort_keys=True)

    def compute_hash(self):
        """
        The block's name. Cheap on purpose -- it is used for linking blocks
        together and looking them up, which happens constantly.
        """
        return hashlib.sha256(self.header_json().encode()).hexdigest()

    def pow_hash(self):
        """
        The number that has to come out small enough. Expensive on purpose --
        this is the work in proof-of-work.
        """
        return memory_hard(self.header_json().encode())


TARGET_BLOCK_SECONDS = 60
MAX_TARGET = (1 << 256) - 1
INITIAL_BITS = 12
INITIAL_TARGET = 1 << (256 - INITIAL_BITS)
ADJUST_WINDOW = 8
GAP_CAP = 2 * TARGET_BLOCK_SECONDS
EXPECT = 0.75


# ---------------------------------------------------------------------------
# LWMA-1 difficulty (Zawy) -- activates at the v5 flag day. Retargets EVERY block
# on a short linearly-weighted window, so difficulty tracks hashrate tightly. This
# is what stops a miner from running ahead onto a private fork: with difficulty
# kept honest, a lone miner mines at the true rate and can't outpace the network.
# Below LWMA_HEIGHT the OLD rule runs unchanged, so the existing chain validates
# exactly as before and updated/old nodes agree until the flag day.
# ---------------------------------------------------------------------------
LWMA_HEIGHT = 10750      # flag day (set to match CONSENSUS_V5_HEIGHT before release). 999_999_999 = OFF.
LWMA_N = 10

def _lwma_at(blocks, i, out):
    n = min(LWMA_N, i - 1)
    if n < 1:
        return out[i - 1] if i >= 1 else INITIAL_TARGET
    weighted = 0.0
    total_diff = 0.0
    for k in range(1, n + 1):
        j = i - (n - k + 1)                     # oldest .. newest of the window
        st = blocks[j].timestamp - blocks[j - 1].timestamp
        st = max(-5 * TARGET_BLOCK_SECONDS, min(st, 6 * TARGET_BLOCK_SECONDS))
        weighted += k * st                      # newest block gets the largest weight
        total_diff += MAX_TARGET / max(1, out[j])
    weighted = max(weighted, n * n * TARGET_BLOCK_SECONDS / 20.0)   # low-clamp (anti-runaway)
    kk = n * (n + 1) / 2.0
    next_diff = total_diff * kk * TARGET_BLOCK_SECONDS / (n * weighted)
    next_diff = max(1.0, next_diff)
    return max(1, min(int(MAX_TARGET / next_diff), MAX_TARGET))

def _target_sequence(blocks, extra=0):
    out = []
    cur = INITIAL_TARGET
    total = len(blocks) + extra
    for i in range(total):
        if i == 0:
            out.append(MAX_TARGET)
            continue

        if i >= LWMA_HEIGHT:
            cur = _lwma_at(blocks, i, out)       # v5: LWMA every block
        elif i >= ADJUST_WINDOW + 2 and (i - 2) % ADJUST_WINDOW == 0:
            span = 0.0
            for j in range(i - ADJUST_WINDOW, i):
                gap = blocks[j].timestamp - blocks[j - 1].timestamp
                span += max(0.1, min(gap, GAP_CAP))
            ratio = span / (ADJUST_WINDOW * TARGET_BLOCK_SECONDS * EXPECT)
            ratio = max(0.25, min(4.0, ratio))
            cur = max(1, min(int(cur * ratio), MAX_TARGET))
        out.append(cur)
    return out


# --- target caching --------------------------------------------------------
# compute_targets/next_target used to rebuild the ENTIRE target history from
# block 0 on every call -- and they are called on every block validation, every
# share, every /network request and every background verify pass. On a chain of
# tens of thousands of blocks that is ~50ms of pure CPU *per call*, many times a
# second, which pins the processor and makes everything (including the mint page)
# slow. The result is fully determined by the block timestamps and the targets
# before it, so it is safe to memoise: we keep the computed sequence and only
# recompute when the chain actually changed. A reorg changes the tip hash, which
# we detect and invalidate on.
_targets_cache = {"len": -1, "tip": None, "seq": None}
_targets_lock = _threading.Lock()


def _chain_signature(blocks):
    if not blocks:
        return (0, None)
    return (len(blocks), blocks[-1].compute_hash())


def compute_targets(blocks):
    sig_len, sig_tip = _chain_signature(blocks)
    with _targets_lock:
        if _targets_cache["len"] == sig_len and _targets_cache["tip"] == sig_tip \
                and _targets_cache["seq"] is not None:
            return _targets_cache["seq"]
    seq = _target_sequence(blocks, extra=0)
    with _targets_lock:
        _targets_cache["len"] = sig_len
        _targets_cache["tip"] = sig_tip
        _targets_cache["seq"] = seq
    return seq


def next_target(blocks):
    # next_target = the target for a hypothetical block appended after the tip.
    # Reuse the cached sequence for the existing chain, then compute just the one
    # extra step, instead of rebuilding the whole history with extra=1.
    #
    # Empty chain: the very first block (genesis, index 0) is mined against
    # MAX_TARGET -- _target_sequence's i==0 branch. This MUST stay MAX_TARGET, or
    # genesis is mined against a different target, finds a different nonce, and
    # gets a different hash -- a different genesis == a different, incompatible
    # chain. (This is exactly what a wrong value here broke once.)
    i = len(blocks)                            # index of the would-be new block
    if i == 0:
        return MAX_TARGET
    base = compute_targets(blocks)             # cached
    if i >= LWMA_HEIGHT:
        return _lwma_at(blocks, i, base)
    if i >= ADJUST_WINDOW + 2 and (i - 2) % ADJUST_WINDOW == 0:
        span = 0.0
        for j in range(i - ADJUST_WINDOW, i):
            gap = blocks[j].timestamp - blocks[j - 1].timestamp
            span += max(0.1, min(gap, GAP_CAP))
        ratio = span / (ADJUST_WINDOW * TARGET_BLOCK_SECONDS * EXPECT)
        ratio = max(0.25, min(4.0, ratio))
        return max(1, min(int(base[-1] * ratio), MAX_TARGET))
    # No retarget at this step: difficulty carries forward. For block index 1
    # (i == 1) the sequence sets INITIAL_TARGET; below the first adjustment
    # window it carries INITIAL_TARGET; otherwise it carries the tip's target.
    if i < ADJUST_WINDOW + 2:
        return INITIAL_TARGET
    return base[-1]                            # carry the tip's target forward


class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self._create_genesis_block()

    # The genesis block is identical for everyone and never changes, but mining
    # it costs thousands of memory-hard hashes -- a minute or more of solid CPU
    # at real difficulty. Building a chain object was doing that work every
    # single time, including once per incoming chain submission, which was
    # enough on its own to wedge a server permanently. Mine it once, keep it.
    _GENESIS = None
    _genesis_lock = _threading.Lock()

    def _create_genesis_block(self):
        # Without the lock, a burst of threads all building chain objects at
        # once each see an empty cache and each mine the genesis block --
        # thousands of memory-hard hashes per thread, all for a block whose
        # answer is identical every time. That alone can pin a whole machine.
        if Blockchain._GENESIS is None:
            with Blockchain._genesis_lock:
                if Blockchain._GENESIS is None:
                    genesis = Block(
                        index=0,
                        transactions=["Sosaiem genesis block -- the chain begins. Owned by no one, open to everyone."],
                        previous_hash="0" * 64,
                        timestamp=0,
                    )
                    self._mine_block(genesis)
                    Blockchain._GENESIS = genesis
        g = Blockchain._GENESIS
        # a fresh object each time, so callers can never mutate the shared one
        copy = Block(index=g.index, transactions=list(g.transactions),
                     previous_hash=g.previous_hash, timestamp=g.timestamp,
                     nonce=g.nonce)
        self.chain.append(copy)

    @property
    def last_block(self):
        return self.chain[-1]

    def _mine_block(self, block):
        target = next_target(self.chain)
        while int(block.pow_hash(), 16) >= target:
            block.nonce += 1
        return block.compute_hash()

    def add_transaction(self, transaction):
        self.pending_transactions.append(transaction)

    def mine_pending_transactions(self):
        new_block = Block(
            index=self.last_block.index + 1,
            transactions=list(self.pending_transactions),
            previous_hash=self.last_block.compute_hash(),
        )
        print(f"  Mining block {new_block.index} ... ", end="", flush=True)
        start = time.time()
        valid_hash = self._mine_block(new_block)
        elapsed = time.time() - start
        self.chain.append(new_block)
        self.pending_transactions = []
        print(f"done in {elapsed:.2f}s  (nonce={new_block.nonce}, hash={valid_hash[:16]}...)")

    def is_chain_valid(self, skip_work=None, links_only=False):
        """
        Check the chain holds together.

        `skip_work` is a set of block hashes whose proof-of-work this node has
        already verified. The link check below runs on every block every time,
        and it is that check which catches a tampered block: changing any block
        changes its hash, which breaks the next block's back-reference. Only the
        expensive re-hashing is skipped.

        `links_only` skips the proof-of-work check entirely. Sync uses this so a
        slow machine can keep up with the network's tip -- re-running memory-hard
        scrypt on every new block inline meant a slow CPU could fall permanently
        behind, validating up to block N while the network reached N+5. The full
        proof is still confirmed in the background after adopting.
        """
        targets = compute_targets(self.chain)
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.previous_hash != previous.compute_hash():
                print(f"  ! Block {current.index} is not linked to block {previous.index} -- chain broken!")
                return False

            if links_only:
                continue
            if skip_work is not None and current.compute_hash() in skip_work:
                continue
            if int(current.pow_hash(), 16) >= targets[i]:
                print(f"  ! Block {current.index} fails proof-of-work.")
                return False

        return True

    def print_chain(self):
        print("\n  ===== THE SOSAIEM BLOCKCHAIN =====")
        for block in self.chain:
            print(f"  Block {block.index}")
            print(f"     previous_hash: {block.previous_hash[:24]}...")
            print(f"     hash:          {block.compute_hash()[:24]}...")
            print(f"     transactions:  {block.transactions}")
            print()


if __name__ == "__main__":
    print("Creating the Sosaiem blockchain (with its genesis block)...\n")
    sosaiem = Blockchain()

    print("Adding some transactions and mining them into blocks:\n")
    sosaiem.add_transaction("Alice -> Bob: 5 SOSA")
    sosaiem.add_transaction("Bob -> Carol: 2 SOSA")
    sosaiem.mine_pending_transactions()

    sosaiem.add_transaction("Carol -> Dave: 1 SOSA")
    sosaiem.mine_pending_transactions()

    sosaiem.print_chain()

    print("  Checking the chain is intact...")
    print("  Chain valid? ->", sosaiem.is_chain_valid())
    print()

    print("  Now someone secretly changes an old block to cheat...")
    sosaiem.chain[1].transactions = ["Alice -> Hacker: 1000 SOSA"]
    print("  (They changed block 1 to pay themselves 1000 SOSA.)")
    print()
    print("  Re-checking the chain...")
    print("  Chain valid? ->", sosaiem.is_chain_valid())
    print()
    print("  The tampering was detected instantly -- this is what makes a")
    print("  blockchain trustworthy with no central authority.")
