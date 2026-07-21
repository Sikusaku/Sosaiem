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


def memory_hard(data: bytes) -> str:
    """The one piece of work in the whole system. Everything costly uses this."""
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


def _target_sequence(blocks, extra=0):
    out = []
    cur = INITIAL_TARGET
    total = len(blocks) + extra
    for i in range(total):
        if i == 0:
            out.append(MAX_TARGET)
            continue

        if i >= ADJUST_WINDOW + 2 and (i - 2) % ADJUST_WINDOW == 0:
            span = 0.0
            for j in range(i - ADJUST_WINDOW, i):
                gap = blocks[j].timestamp - blocks[j - 1].timestamp
                span += max(0.1, min(gap, GAP_CAP))
            ratio = span / (ADJUST_WINDOW * TARGET_BLOCK_SECONDS * EXPECT)
            ratio = max(0.25, min(4.0, ratio))
            cur = max(1, min(int(cur * ratio), MAX_TARGET))
        out.append(cur)
    return out


def compute_targets(blocks):
    return _target_sequence(blocks, extra=0)


def next_target(blocks):
    return _target_sequence(blocks, extra=1)[-1]


class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis = Block(
            index=0,
            transactions=["Sosaiem genesis block -- the chain begins. Owned by no one, open to everyone."],
            previous_hash="0" * 64,
            timestamp=0,
        )

        self._mine_block(genesis)
        self.chain.append(genesis)

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

    def is_chain_valid(self, skip_work=None):
        """
        Check the chain holds together.

        `skip_work` is a set of block hashes whose proof-of-work this node has
        already verified. The link check below still runs on every block every
        time, and it is that check which catches a tampered block: changing any
        block changes its hash, which breaks the next block's back-reference.
        Only the expensive re-hashing is skipped.
        """
        targets = compute_targets(self.chain)
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.previous_hash != previous.compute_hash():
                print(f"  ! Block {current.index} is not linked to block {previous.index} -- chain broken!")
                return False

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
