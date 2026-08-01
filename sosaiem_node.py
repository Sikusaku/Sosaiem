"""Sosaiem node: mining, feeless stake-voting transfers, and P2P networking."""

import sys
import os
import json
import time
import uuid
import random
import socket
import hashlib
# HARD CAP: no socket operation anywhere may hang longer than this. Without it,
# a dead or slow peer (common during a hash war) freezes a worker thread forever;
# once every worker is frozen, the node can't answer the mint and appears 'down'.
socket.setdefaulttimeout(30)
import threading
import collections
import urllib.parse
import urllib.request

import portmap
import nostrseed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer as _BaseHTTPServer


from concurrent.futures import ThreadPoolExecutor


class ThreadingHTTPServer(_BaseHTTPServer):
    # Set at class level so it takes effect *before* the socket binds. This is
    # what frees the port the moment the app closes; without it Windows holds
    # the port for a minute or two and reopening the wallet fails to start.
    allow_reuse_address = True
    daemon_threads = True

    # A public node gets hammered by random internet traffic. Spawning one
    # unbounded thread per request piled up until the OS refused new threads
    # ("can't start new thread") and the whole node stopped answering. A fixed
    # pool caps concurrency: requests queue instead of exhausting the machine.
    _pool = None

    def process_request(self, request, client_address):
        if self._pool is None:
            # 64 workers was sized for a big server. On a small 2-core / 2 GB box
            # it let dozens of requests -- several of them doing memory-hard work
            # -- run at once, spiking memory into swap and stalling everything for
            # tens of seconds (CPU idle, requests waiting on memory). A modest pool
            # keeps the box responsive; extra requests queue briefly instead of all
            # piling onto memory at once. Scale with cores, capped low.
            import os as _os
            workers = max(8, min(24, (_os.cpu_count() or 2) * 6))
            type(self)._pool = ThreadPoolExecutor(max_workers=workers,
                                                  thread_name_prefix="sos-http")
        self._pool.submit(self._handle_pooled, request, client_address)

    def _handle_pooled(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            pass
        finally:
            try:
                self.shutdown_request(request)
            except Exception:
                pass

def threads_from_args(argv=None):
    """
    Read --threads=N from the command line.

    Lives here so the node, the miner and the wallet all honour it. It used to
    be parsed only in the node's own startup, so anyone running the desktop
    miner with --threads=1 was quietly ignored and got the default instead.
    """
    for arg in (argv if argv is not None else sys.argv[1:]):
        if arg.startswith("--threads="):
            try:
                return max(1, min(64, int(arg.split("=", 1)[1])))
            except ValueError:
                return None
    return None


def _unfreeze_windows_console():
    """
    Stop Windows pausing the whole program when someone clicks in the window.

    Command Prompt ships with "QuickEdit Mode" on. Clicking anywhere inside the
    console -- even by accident, even once -- suspends the entire process until
    a key is pressed. Nothing says so. The node simply stops: it stops syncing,
    stops answering, and quietly falls further and further behind, still showing
    its last state as though it were working. Press Enter and it springs back to
    life and catches up in one jump, which looks like a mysterious stall that
    mysteriously healed. It was never a stall; the program was frozen.
    """
    if os.name != "nt":
        return
    try:
        import ctypes
        k = ctypes.windll.kernel32
        handle = k.GetStdHandle(-10)          # STD_INPUT_HANDLE
        mode = ctypes.c_uint32()
        if not k.GetConsoleMode(handle, ctypes.byref(mode)):
            return
        ENABLE_QUICK_EDIT = 0x0040
        ENABLE_EXTENDED_FLAGS = 0x0080
        k.SetConsoleMode(handle,
                         (mode.value & ~ENABLE_QUICK_EDIT) | ENABLE_EXTENDED_FLAGS)
    except Exception:
        pass


from wallet import Wallet, verify_signature, WalletLocked, WrongPassword
from blockchain import (Blockchain, Block, next_target, compute_targets,
                        MAX_TARGET, memory_hard, LWMA_HEIGHT)
from coin import (compute_balances, total_minted, remaining_supply,
                  make_transfer, make_reward, transfer_is_valid, amount_is_sane,
                  _address_from_pubkey, BLOCK_REWARD, MAX_SUPPLY,
                  TARGET_BLOCK_SECONDS)


SYNC_INTERVAL = 3

# A validator counts toward the vote for this long after we last heard from it.
# Long enough to survive a restart or a slow connection, short enough that
# wallets closed days ago do not hold everyone else's transfers hostage.
ACTIVE_VALIDATOR_WINDOW = 15 * 60

# --- versions -----------------------------------------------------------
# PROTOCOL_VERSION describes the *consensus rules*: what makes a block or a
# transfer valid. Two nodes with different protocol versions may disagree about
# the chain itself and quietly drift apart, so this number exists to make that
# disagreement visible instead of silent.
#
# Bump it ONLY when a rule changes -- the block reward, the supply cap, how a
# hash is built, what a valid signature is. When you do, give people an
# activation height and time to update, or the network splits into two coins.
#
# NODE_VERSION is just the build. Change it freely: new endpoints, a nicer
# window, faster syncing, bug fixes that only tighten what was already invalid.
# Nobody has to agree on it and nothing can split over it.
PROTOCOL_VERSION = 4
NODE_VERSION = "3.0.0"    # Sosaiem 3.0: unified app, honest sync + mining watchdog (auto-recover from fork drift), transfer rebroadcast, balance de-dup fix, fair-work payout (flag day 15555). v6 fork choice active since 11750.

# Blocks may carry a small tag naming the build that made them. It is accepted
# and recorded, never required. A rule that forces everyone onto a particular
# build is a rule somebody had to choose, and choosing the activation height
# wrongly invalidates real work -- which is exactly what happened when it was
# set at block 400 while honest miners were already past it. Adoption does the
# same job on its own: whoever runs current software keeps up.
BUILD_MARKER = 220

DISCOVERY_PORT = 54546
DISCOVERY_INTERVAL = 4

_CANONICAL_GENESIS_HASH = Blockchain().chain[0].compute_hash()

# ---- abuse / DoS limits (none of these affect consensus) ----
MAX_BODY_CHAIN = 32 * 1024 * 1024     # /submit_chain may carry the whole chain
MAX_BODY_DEFAULT = 1024 * 1024        # every other request body
RATE_WINDOW = 10.0                    # seconds
RATE_MAX = 300                        # max requests per remote IP per window
MAX_TRANSFERS = 10000                 # stored transfers cap
MAX_VOTE_TABLES = 10000               # distinct transfers we track votes for
MAX_REGISTRY = 20000                  # known validators cap

_RATE = collections.defaultdict(collections.deque)
_RATE_LOCK = threading.Lock()


def rate_allowed(ip):
    """Simple per-IP sliding-window limiter so one address can't flood the node."""
    now = time.time()
    with _RATE_LOCK:
        dq = _RATE[ip]
        cutoff = now - RATE_WINDOW
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= RATE_MAX:
            return False
        dq.append(now)
        if len(_RATE) > 20000:                       # keep the table itself bounded
            for k in [k for k, v in _RATE.items() if not v]:
                del _RATE[k]
        return True


SHARE_EASE = 32
# Every share in a block must be re-verified by every node, and a share now
# costs real memory and time. 2000 of them would make a single block take
# most of a minute to check, which is a denial-of-service dressed as a block.
MAX_SHARES_PER_BLOCK = 128

# How many blocks back a work-share stays payable. Without this, a share only
# counted for the exact block it was mined against, so anyone whose share
# arrived a second late earned nothing at all -- and the miner who found blocks
# fastest kept taking whole rewards. Five blocks is a few minutes of grace:
# long enough that ordinary network delay never costs anyone their work, short
# enough that the ledger stays easy to check.
SHARE_WINDOW = 15


# ===========================================================================
# FAIR-WORK PAYOUT (Path B) -- DORMANT until FAIRWORK_HEIGHT is set.
#
# Goal: any device, any speed -- even the weakest -- always gets paid for the
# exact work it did. Nobody is ever left out by being slow.
#
# How it stays SAFE (no fork, no share-chain desync): the payout is still
# computed ENTIRELY from the shares embedded in the block, which every node
# already agrees on. Same input -> same output on every node. This is the live
# in-block ("paylist") payout, made continuous and inclusive -- NOT a return to
# the fragile separate share-chain.
#
# Three changes vs. today, ALL off until the flag day:
#   1. FAIRWORK_SHARE_EASE -- shares are far easier, so even a Raspberry Pi lands
#      one every block or two. (bigger number = easier = weaker devices included)
#   2. FAIRWORK_WINDOW -- a share counts if anchored to ANY block in a wider
#      recent window, so slow work isn't thrown away when the tip ticks over.
#   3. Difficulty-weighted split -- each share carries how hard it actually was;
#      the reward splits by SUMMED difficulty, not raw share count. This is the
#      fairest map of work->pay: someone who did 10x the work earns 10x, even if
#      variance meant they landed fewer individual shares.
#
# FAIRWORK_HEIGHT = None means OFF everywhere: deploying this file changes
# nothing. It is switched on only at a coordinated block height after real-node
# testing (including a deliberately-throttled "Pi" node proving it gets paid).
# ===========================================================================
FAIRWORK_HEIGHT = 15555           # FLAG DAY: fair-work payout activates at block 15555.
FAIRWORK_SHARE_EASE = 4096        # shares ~4096x easier than a block -> any device lands them
FAIRWORK_WINDOW = 30              # a share stays payable across ~30 blocks (~30 min)
FAIRWORK_MAX_SHARES = 256         # more room, since easy shares are more numerous


def fairwork_active(height):
    h = FAIRWORK_HEIGHT
    return h is not None and height is not None and height >= h


def fairwork_share_target(block_target):
    """The (much easier) share target under the fair-work rule."""
    return min(block_target * FAIRWORK_SHARE_EASE, MAX_TARGET)


def share_target_at(block_target, height):
    """
    The share target in force at a given height. Below the fair-work flag day it
    is the normal target; at/after activation it is the (much easier) fair-work
    target so any device lands shares. Builder and validator both call this with
    the SAME height, so they always agree on which shares are valid -- that is
    what keeps the flag day fork-free among updated nodes.
    """
    if fairwork_active(height):
        return fairwork_share_target(block_target)
    return share_target_for(block_target)


def share_difficulty(share_id_hex, share_target):
    """
    How much work a share proves, as a positive weight. A share whose hash is far
    UNDER the target proved more work than one that barely cleared it, so we weight
    by target/hash_value. This is what makes the split track true work, not luck:
    across many shares it converges exactly to each miner's hashrate share. A
    minimum weight of 1 guarantees any valid share -- from any device -- is paid.
    """
    try:
        hv = int(share_id_hex, 16)
        if hv <= 0:
            return 1.0
        w = share_target / hv
        return w if w >= 1.0 else 1.0
    except Exception:
        return 1.0




# --- transfers-in-blocks (offline-transfer settlement) ----------------------
# Transfers move from the old online-voting system into the block chain: a
# sender self-mines a small proof-of-work on their transfer, and miners carry it
# into a block for free. The chain's order becomes the referee that stops
# double-spends, so a transfer settles even if the recipient (or every other
# holder) is offline.
#
# THIS IS DORMANT UNTIL ACTIVATED. Until the chain reaches TRANSFERS_ACTIVATION
# _HEIGHT, no block may contain a transfer and nothing below changes how the node
# behaves -- the live chain runs exactly as it did before. Set the height to a
# real block number ONLY after a two-node test has confirmed the flow. The
# sentinel below (a huge number) means "off".
TRANSFERS_ACTIVATION_HEIGHT = 4500          # transfers go live at this block
# On-chain settlement flag day. AT this height, updated nodes STOP vote-confirming
# transfers into the side-cache and settle them in blocks only -- permanent, no
# revert, every node agrees. Like the payout activations, EVERY node must be on
# 2.15.15+ before this block; one still voting past it would double-count a
# transfer others settled on-chain and drift onto a minority view. Left far in the
# future so 2.15.15 behaves EXACTLY like 2.15.14 until you schedule it: set this to
# (current height + a few hundred), announce it, let everyone update, then release.
# ============================ CONSENSUS v5 FLAG DAY ==========================
# ONE height at which everything switches on together for every updated node:
#   * LWMA difficulty (stops runaway forks -- keeps difficulty honest per block)
#   * on-chain transfer settlement (reliable transfers/escrow, in blocks)
# Below this height the node behaves EXACTLY like v4 (same difficulty, same
# transfer rules), so updated and not-yet-updated nodes agree until the flag day.
# To schedule the flag day: set LWMA_HEIGHT in blockchain.py to (current height +
# a few hundred), which drives BOTH changes. 999_999_999 = OFF (safe to deploy now).
CONSENSUS_V5_HEIGHT = LWMA_HEIGHT     # transfers activate at the same height as LWMA
# ============================================================================

# ============================ CONSENSUS v6 FLAG DAY ==========================
# TWO consensus fixes switch on together here, for every updated node:
#   * work-based fork choice  -- the heaviest (most cumulative work) chain wins,
#     not merely the longest. LWMA makes per-block work vary, so "longest" can
#     pick a longer LOW-work fork over a shorter honest one; this closes that.
#   * median-time-past timestamps -- a block's timestamp must exceed the median
#     of the previous 11, so a miner can't feed LWMA fake (backwards) times to
#     game difficulty. Fully deterministic (no wall-clock), so no node's clock
#     can make it disagree.
# BOTH are consensus changes: an updated node and a not-yet-updated one will
# pick different tips / accept different blocks above this height. So this MUST
# be a coordinated flag day set ABOVE the current tip, announced, with everyone
# on the same build before it is reached -- exactly like the v5 flag day.
# Set to (current height + a few hundred) once the network is unified. A value
# at/above the live tip means the rules are OFF on every node running this build,
# so it is always SAFE to deploy first and schedule second.
CONSENSUS_V6_HEIGHT = 11750      # 999_999_999 = OFF (safe to deploy now)


def v6_active(height):
    """True once the chain has reached the v6 flag day."""
    return height is not None and height >= CONSENSUS_V6_HEIGHT


TRANSFERS_ONCHAIN_HEIGHT = CONSENSUS_V5_HEIGHT   # transfers go on-chain at the flag day
TRANSFER_WORK_TARGET = 2 ** 236                 # send-time work: a few seconds
MAX_TRANSFERS_PER_BLOCK = 64


def transfers_active(height):
    """True only once the chain has reached the activation height."""
    return height is not None and height >= TRANSFERS_ACTIVATION_HEIGHT


def transfers_onchain_only(height):
    """True once the coordinated flag day is reached: settle in blocks, stop voting."""
    return height is not None and height >= TRANSFERS_ONCHAIN_HEIGHT


def _transfer_work_core(tx):
    # the work is bound to this exact signed transfer, so a stamp can't be reused
    return (f"SOSA-xfer|{tx.get('from')}|{tx.get('to')}|{tx.get('amount')}"
            f"|{tx.get('signature')}").encode()


def transfer_work_hash(tx, nonce):
    return hashlib.sha256(_transfer_work_core(tx) + f"|{nonce}".encode()).hexdigest()


def transfer_work_is_valid(tx):
    nonce = tx.get("work_nonce")
    if not isinstance(nonce, int) or nonce < 0:
        return False
    return int(transfer_work_hash(tx, nonce), 16) < TRANSFER_WORK_TARGET


def stamp_transfer(tx):
    """Sender's PC does the send-time work, then broadcasts. Returns tx + nonce."""
    nonce = 0
    while True:
        if int(transfer_work_hash(tx, nonce), 16) < TRANSFER_WORK_TARGET:
            out = dict(tx)
            out["work_nonce"] = nonce
            return out
        nonce += 1


def share_hash(prev_hash, address, nonce):
    """
    A work share proves a miner was genuinely working, and shares decide how
    the block reward is split.

    This has to cost exactly what block-finding costs. If shares were cheap
    SHA-256 while blocks were memory-hard, someone with fast dedicated hardware
    could flood the network with shares and collect most of the reward without
    ever doing the expensive work -- and honest miners would be forced to
    include those shares in the blocks they found. Hardening the block alone
    would have left the front door open.
    """
    return memory_hard(f"SOSA-share|{prev_hash}|{address}|{nonce}".encode())


def share_target_for(block_target):
    return min(block_target * SHARE_EASE, MAX_TARGET)


def split_amounts(reward, counts):
    total = sum(counts.values())
    if reward <= 0 or total <= 0:
        return {}
    out = {}
    running = 0.0
    for addr in sorted(counts):
        amt = round(reward * counts[addr] / total, 8)
        out[addr] = amt
        running = round(running + amt, 8)
    dust = round(reward - running, 8)
    if abs(dust) > 0:
        best = sorted(counts, key=lambda a: (-counts[a], a))[0]
        out[best] = round(out[best] + dust, 8)
    return {a: amt for a, amt in out.items() if amt > 0}


def split_amounts_weighted(reward, weights):
    """
    Split a reward by difficulty-WEIGHTED work, deterministically.

    `weights` maps address -> total proven work (a float sum of per-share
    difficulty). Everyone with any weight gets paid in proportion; the split is
    computed in a fixed order and any rounding dust is handed to the largest
    contributor, so EVERY node with the same weights produces the identical
    payout down to the last satoshi. That determinism is what lets this live
    inside a block without a separate ledger to disagree about.

    Weights are quantised to a fixed number of decimals before use, so two nodes
    that computed the same shares can't diverge on float representation.
    """
    if reward <= 0 or not weights:
        return {}
    # quantise to 8 decimals so float noise can't make nodes disagree
    q = {a: round(float(w), 8) for a, w in weights.items() if w and w > 0}
    total = round(sum(q.values()), 8)
    if total <= 0:
        return {}
    out = {}
    running = 0.0
    for addr in sorted(q):
        amt = round(reward * q[addr] / total, 8)
        out[addr] = amt
        running = round(running + amt, 8)
    dust = round(reward - running, 8)
    if abs(dust) > 0:
        # dust to the largest contributor (ties broken by address, deterministic)
        best = sorted(q, key=lambda a: (-q[a], a))[0]
        out[best] = round(out[best] + dust, 8)
    return {a: amt for a, amt in out.items() if amt > 0}


# ---------------------------------------------------------------------------
# SHARE-CHAIN -- step 1: format + proof/id hash + link validation.
#
# Shares are becoming a chain of their own. Each share names the share before
# it, so the whole record of who-worked links together and no single miner can
# quietly leave others out of the payout. This block adds only the foundation:
# the share format, the memory-hard hash that is both its proof of work and its
# identity, and the check that a share links to one we already know.
#
# NOTHING here is wired into live consensus. These are standalone pieces,
# proven in isolation first, exactly the way the transfer logic was built and
# tested before anything depended on it. The live chain behaves identically.
# ---------------------------------------------------------------------------

SHARECHAIN_GENESIS = "0" * 64   # the share_prev that a first-ever share names

# SHARE-CHAIN -- step 3: difficulty. Rather than give shares their own
# timestamp-based retarget (which a miner could skew with fake times), the
# share-chain difficulty rides the block difficulty, which already retargets
# itself to a steady 60s. A share is this many times easier to find than a
# block; at a 60s block that lands a share roughly every 3s across the whole
# network -- a fine-grained, continuous record of who is working. Because it is
# derived from the block target, it adjusts automatically as hashrate comes and
# goes, and there is nothing here a miner can lie about.
SHARECHAIN_EASE = 20


def sharechain_target(block_target):
    """The share-chain proof target, derived from the current block target."""
    return min(block_target * SHARECHAIN_EASE, MAX_TARGET)


# SHARE-CHAIN -- step 4: how far back the payout looks. A block's reward is
# split across the last PPLNS_WINDOW shares in the share-chain. At ~3s a share
# that is about this many minutes of recent work -- long enough that a single
# lucky block doesn't decide everything, short enough that payouts track what
# people are doing now. Everyone who worked in the window gets paid in
# proportion, every time, no matter who happens to find the block.
PPLNS_WINDOW = 300

# How many shares must be in the payout window before the hard rule will REJECT
# a block. Below this the share-chain isn't authoritative yet -- most commonly
# just after a restart while it reloads and re-syncs -- so blocks are accepted
# rather than frozen out. This is the guard that stops an empty share-chain from
# deadlocking the whole network while keeping anti-hoarding enforcement once the
# chain is genuinely populated.
SCHAIN_ENFORCE_MIN = 20

# Uncle inclusion: on a real network with lag, a smaller miner's share can be
# out-raced -- a bigger miner extends the chain past it before it lands, so it
# ends up a valid-but-orphaned sibling. Without help those shares count for
# nothing and small miners get shorted. So a share may reference up to
# MAX_UNCLES recent orphaned shares; those references are committed into the
# chain everyone agrees on, and the payout credits uncles too. That is how a
# share that lost the race still gets paid for its real work.
MAX_UNCLES = 3
UNCLE_DEPTH = 12          # an uncle must be within this many heights of the tip

# ANCHOR-RECENCY (fix, step 6): a share only counts toward a payout if it was
# mined against a RECENT block. Before this, a long-dormant branch -- old miners'
# shares anchored to blocks from ages ago -- kept full cumulative weight, could
# win tip selection, and dragged the whole payout window onto people who had
# stopped working, so the miners actually working now got nothing and their
# reward never got split out to them. A currently-active miner always anchors to
# the live tip, so this many blocks of slack (~30 min at a 60s block) never
# excludes real work; it only strips out the stale branch.
SCHAIN_ANCHOR_BLOCKS = 30


def sharechain_share_id(share_prev, block_prev, address, nonce, uncles=()):
    """
    A share-chain share's proof of work AND its identity, in one hash. The
    uncle references are part of what's hashed, so they're committed -- a miner
    can't add or swap uncles after the fact without redoing the work.
    """
    u = ",".join(uncles)
    return memory_hard(
        f"SOSA-schain|{share_prev}|{block_prev}|{address}|{nonce}|{u}".encode()
    )


def make_share(share_prev, block_prev, address, nonce, uncles=()):
    """Build a share-chain share; its id is derived from its own contents."""
    uncles = list(uncles)
    sid = sharechain_share_id(share_prev, block_prev, address, nonce, uncles)
    return {
        "share_prev": share_prev,
        "block_prev": block_prev,
        "address": address,
        "nonce": nonce,
        "uncles": uncles,
        "id": sid,
    }


def share_is_well_formed(share):
    """Structural check: the fields exist with the right types."""
    if not isinstance(share, dict):
        return False
    sp, bp = share.get("share_prev"), share.get("block_prev")
    ad, nc = share.get("address"), share.get("nonce")
    if not isinstance(sp, str) or not isinstance(bp, str):
        return False
    if not isinstance(ad, str) or not ad.startswith("SOSA"):
        return False
    if not isinstance(nc, int):
        return False
    un = share.get("uncles", [])
    if not isinstance(un, list) or len(un) > MAX_UNCLES:
        return False
    if not all(isinstance(u, str) for u in un):
        return False
    if len(set(un)) != len(un):          # no repeated uncle references
        return False
    return True


def share_id_is_valid(share):
    """
    The stored id must equal the hash of the share's own contents, so a share
    cannot lie about its identity or claim work it did not do.
    """
    if not share_is_well_formed(share):
        return False
    want = sharechain_share_id(share["share_prev"], share["block_prev"],
                               share["address"], share["nonce"],
                               share.get("uncles", []))
    return share.get("id") == want


def share_meets_target(share, share_chain_target):
    """The proof: the share's own hash must fall under the share-chain target."""
    if not share_id_is_valid(share):
        return False
    return int(share["id"], 16) < share_chain_target


def share_link_ok(share, known_ids):
    """
    The link check: a share must point at a share we already know (its parent
    in the share-chain), or at the genesis sentinel if it is the very first.
    `known_ids` is the set of share ids currently in the share-chain.
    """
    if not share_is_well_formed(share):
        return False
    sp = share["share_prev"]
    if sp == SHARECHAIN_GENESIS:
        return True
    return sp in known_ids


# ---------------------------------------------------------------------------
# SHARE-CHAIN -- step 2: the store, heaviest-chain selection, reorg, pruning.
#
# Shares now link into a chain; this holds that chain. The rule that makes the
# whole fix work lives here: the tip is whichever share sits at the end of the
# HEAVIEST branch (the most cumulative work). An honest chain that includes
# everyone's shares out-weighs any one miner's lonely self-only chain, so the
# lonely chain loses and orphans -- which is what stops a dominant miner from
# leaving people out. The tie-break is deterministic (by id), so every node,
# whatever order shares arrive in, agrees on the same tip.
#
# Still standalone: no live path builds or reads a ShareChain yet.
# ---------------------------------------------------------------------------

class ShareChain:
    def __init__(self):
        self.shares = {}      # id -> share dict
        self.work = {}        # id -> this share's own work weight
        self.cum = {}         # id -> cumulative work from genesis through this id
        self.height = {}      # id -> number of shares from genesis through this id
        self.tip = None       # id at the end of the heaviest branch (or None)

    def has(self, sid):
        return sid in self.shares

    def _heavier(self, a, b):
        """Is share `a` a strictly better tip than share `b`? More cumulative
        work wins; on an exact tie the smaller id wins, so the choice is the
        same on every node regardless of arrival order."""
        if b is None:
            return True
        ca, cb = self.cum[a], self.cum[b]
        if ca != cb:
            return ca > cb
        return a < b

    def add(self, share, work=1, allow_root=False, verify=True):
        """
        Add one share. It must be well-formed, carry a valid id (its own proof),
        and link to a parent we already hold (or genesis). Returns True if it
        was accepted, False if rejected. Updates the tip -- which is how a
        heavier branch quietly takes over (a reorg): the tip simply becomes
        whichever leaf now has the most cumulative work. `allow_root` is only
        used when reloading a pruned snapshot from disk: the oldest kept share's
        parent no longer exists, so it legitimately roots the kept range.
        `verify=False` is for reloading OUR OWN saved cache on startup: those
        shares were already proof-checked when we first accepted them, so we skip
        the per-share memory-hard re-proof (thousands of them was a minutes-long
        boot hang that took the seed offline) and only require the fields we index.
        """
        if verify:
            if not share_id_is_valid(share):
                return False
        elif not (isinstance(share, dict) and isinstance(share.get("id"), str)
                  and "share_prev" in share and "address" in share):
            return False
        sid = share["id"]
        if sid in self.shares:
            return False                       # already have it
        sp = share["share_prev"]
        if sp == SHARECHAIN_GENESIS:
            base_cum, base_h = 0, 0
        elif sp in self.shares:
            base_cum, base_h = self.cum[sp], self.height[sp]
        elif allow_root:
            base_cum, base_h = 0, 0            # parent was pruned; root the range
        else:
            return False                       # orphan: parent unknown
        self.shares[sid] = share
        self.work[sid] = work
        self.cum[sid] = base_cum + work
        self.height[sid] = base_h + 1
        if self._heavier(sid, self.tip):
            self.tip = sid
        return True

    def chain_from_tip(self, sid=None):
        """The shares from the tip (or a given id) back to genesis, tip first.
        This is the canonical chain everyone agrees on."""
        cur = sid if sid is not None else self.tip
        out = []
        while cur is not None and cur in self.shares:
            s = self.shares[cur]
            out.append(s)
            nxt = s["share_prev"]
            cur = nxt if nxt != SHARECHAIN_GENESIS else None
        return out

    def snapshot(self):
        """All shares as a plain list, for saving to disk. Order doesn't matter
        -- restore() rebuilds the links -- but we write them oldest-first so a
        restore adds parents before children in one clean pass."""
        by_height = sorted(self.shares.values(),
                           key=lambda s: self.height.get(s["id"], 0))
        return by_height

    def restore(self, shares):
        """Rebuild the share-chain from a saved list. Adds in height order,
        retrying any that arrive before their parent, so the whole structure
        (links, work, tip) comes back exactly. This is what lets the share-chain
        survive a restart instead of resetting to empty -- the thing that stalled
        the live chain once the forcing rule was on."""
        if not isinstance(shares, list):
            return 0
        ids = {s.get("id") for s in shares if isinstance(s, dict)}
        # trusted load: these are shares we already proof-checked and saved
        # ourselves. Skip the per-share memory-hard re-proof (that was the boot
        # hang) -- just require an id, and add() with verify=False.
        pending = [s for s in shares
                   if isinstance(s, dict) and isinstance(s.get("id"), str)]
        added = 0
        progress = True
        while pending and progress:
            progress = False
            still = []
            for s in pending:
                sp = s["share_prev"]
                if sp == SHARECHAIN_GENESIS or sp in self.shares:
                    if self.add(s, verify=False):
                        added += 1
                    progress = True
                elif sp not in ids:
                    # its parent was pruned away before the snapshot -- this
                    # share legitimately roots the kept range
                    if self.add(s, allow_root=True, verify=False):
                        added += 1
                    progress = True
                else:
                    still.append(s)      # parent is in the snapshot, just not in yet
            pending = still
        return added

    def tail(self, n, sid=None):
        """The last `n` shares ending at the tip (or given id), oldest first.
        This is the window a payout is computed over (used in step 4)."""
        chain = self.chain_from_tip(sid)      # tip-first
        window = chain[:n]                    # the n nearest the tip
        window.reverse()                      # oldest first
        return window

    def best_recent_tip(self, fresh):
        """The heaviest share whose anchor block is in `fresh` (the recent
        blocks). Once the anchor-recency rule is on, this is the tip a payout
        follows -- so a stale branch, anchored only to old blocks, can no longer
        win selection and starve the miners working now. Falls back to the raw
        heaviest tip if nothing recent qualifies, so the chain never freezes."""
        if not fresh:
            return self.tip
        best = None
        for sid, s in self.shares.items():
            if s.get("block_prev") in fresh and (best is None
                                                 or self._heavier(sid, best)):
                best = sid
        return best if best is not None else self.tip

    def uncle_candidates(self, tip=None, depth=UNCLE_DEPTH, limit=MAX_UNCLES):
        """
        Recent shares we hold that are NOT on the main chain from `tip` -- the
        orphaned siblings that lost the race. A miner references these as uncles
        so their work still gets paid. Deterministic pick (lowest ids) up to the
        cap, within `depth` of the tip so only genuinely recent orphans qualify.
        """
        t = tip if tip is not None else self.tip
        if t is None:
            return []
        main = self.chain_from_tip(t)
        on_main = {s["id"] for s in main}
        referenced = set()
        for s in main:
            referenced.update(s.get("uncles", []))
        tip_h = self.height.get(t, 0)
        cands = [sid for sid, h in self.height.items()
                 if sid not in on_main and sid not in referenced
                 and 0 <= (tip_h - h) <= depth]
        cands.sort()
        return cands[:limit]

    def prune(self, keep):
        """
        Drop shares far behind the tip -- anything more than `keep` deep. The
        payout window plus a safety margin stays; ancient shares that can never
        affect a payout again are discarded so the store doesn't grow forever.
        Shares still on the path to the tip within `keep` are always retained.
        """
        if self.tip is None:
            return 0
        cutoff = self.height[self.tip] - keep
        if cutoff <= 0:
            return 0
        drop = [sid for sid, h in self.height.items() if h < cutoff]
        for sid in drop:
            self.shares.pop(sid, None)
            self.work.pop(sid, None)
            self.cum.pop(sid, None)
            self.height.pop(sid, None)
        return len(drop)


def canonical_payout(share_chain, reward, window=PPLNS_WINDOW, tip=None,
                     fresh=None):
    """
    The fair split of a block reward -- computed from the share-chain itself,
    not chosen by whoever found the block.

    Take the last `window` shares ending at the tip, count how many each
    address contributed, and split the reward in proportion. Because every node
    holds the same share-chain and this is deterministic, every node arrives at
    the exact same payout. The block finder does not get to decide it. A block
    whose reward transactions don't equal this canonical split is rejected
    (step 5) -- which is precisely what forces a winner to pay everyone their
    real share and makes hoarding impossible.

    `fresh`, when given, is the set of recent block hashes a share must be
    anchored to in order to count (the anchor-recency fix). With it, the tip is
    resolved to the heaviest RECENTLY-anchored share and stale shares in the
    window are skipped, so a dormant branch of old miners can no longer capture
    the payout. When `fresh` is None the behaviour is exactly as before -- which
    is what keeps every block below the fix's activation height validating
    identically and stops the network from splitting.
    """
    if tip is None and fresh is not None:
        tip = share_chain.best_recent_tip(fresh)
    shares = share_chain.tail(window, tip)      # oldest-first, up to `window`
    counts = {}
    credited = {s["id"] for s in shares}
    for s in shares:
        if fresh is not None and s.get("block_prev") not in fresh:
            continue                            # stale work no longer counts
        a = s["address"]
        counts[a] = counts.get(a, 0) + 1
        # credit uncles: recent orphaned shares this one references, so a share
        # that lost the propagation race is still paid for its real work. Each
        # uncle is credited exactly once, however many shares point at it. An
        # uncle is held to the same freshness rule as a normal share.
        for uid in s.get("uncles", []):
            if uid in credited:
                continue
            us = share_chain.shares.get(uid)
            if us and (fresh is None or us.get("block_prev") in fresh):
                credited.add(uid)
                ua = us["address"]
                counts[ua] = counts.get(ua, 0) + 1
    return split_amounts(reward, counts)


# ---------------------------------------------------------------------------
# CROSS-BRANCH FAIR PAYOUT  (dormant -- activation height is None)
#
# The linear payout above walks a single line back from the tip, so when two
# miners mine at the same instant they build PARALLEL branches and only the
# branch the tip lands on gets paid -- one miner takes the whole block. That is
# the "no share split / 1 miner per block" bug. This counts EVERY recent valid
# share across ALL branches instead, so concurrent work is paid in proportion.
#
# It is a consensus change, so it stays OFF (activation None) and must NOT be
# switched on until it is verified on a real multi-node network. Deploying this
# file changes nothing on its own.
# ---------------------------------------------------------------------------
SCHAIN_ALLPAY_ACTIVATION_HEIGHT = 6375


# PAYLIST (dormant): pay the reward across the proof-of-work shares recorded IN
# the block itself, not the share-chain. The block's share list is PoW-verified
# by every node and is identical for builder and validator, so "who worked" and
# "who gets paid" become the same set by construction -- nobody who did work is
# skipped because their share didn't happen to link into one node's share-chain
# (the "6 worked, 2 paid" bug). Consensus change -> stays off until a coordinated
# activation height, and must be tested on real nodes first. None = off everywhere.
SCHAIN_PAYLIST_ACTIVATION_HEIGHT = 6500


def paylist_active(height):
    h = SCHAIN_PAYLIST_ACTIVATION_HEIGHT
    return h is not None and height is not None and height >= h


def allpay_active(height):
    h = SCHAIN_ALLPAY_ACTIVATION_HEIGHT
    return h is not None and height is not None and height >= h


def canonical_payout_allwork(share_chain, reward, window=PPLNS_WINDOW, fresh=None):
    """Fair split counting every recent valid share across all branches, not
    just the tip's line. Deterministic: all nodes hold the same converged shares
    and heights, so all compute the same split."""
    tip = (share_chain.best_recent_tip(fresh) if fresh is not None
           else share_chain.tip)
    if tip is None:
        return {}
    top = share_chain.height.get(tip, 0)
    lo = top - window
    counts = {}
    for sid, s in share_chain.shares.items():
        h = share_chain.height.get(sid)
        if h is None or h <= lo or h > top:
            continue
        if fresh is not None and s.get("block_prev") not in fresh:
            continue
        a = s["address"]
        counts[a] = counts.get(a, 0) + 1
    return split_amounts(reward, counts)


# SHARE-CHAIN -- step 5: the forcing rule, and its activation switch.
#
# When active, a block's reward transactions MUST equal the canonical payout
# derived from the share-chain. A block that pays anyone differently -- a
# hoarder paying only itself, most of all -- is rejected by every node. That is
# the whole point: the winner no longer chooses who gets paid, so hoarding
# stops being possible rather than merely discouraged.
#
# It is dormant until SHARECHAIN_ACTIVATION_HEIGHT is set (at ship time, step 8,
# only after real-node testing). While it is None the rule is off everywhere and
# the live chain validates exactly as it does today -- the same safe pattern the
# 4500 transfer switch used.
SHARECHAIN_ACTIVATION_HEIGHT = 5400

# After activation, this many blocks accept EITHER the old in-block split OR the
# new share-chain payout -- so no active miner is stranded the instant the rule
# turns on while word of the update spreads. After the grace window it goes
# hard: only the fair share-chain payout is valid, and a hoarding block is
# rejected for good. This is the gentle cutover we chose.
SHARECHAIN_GRACE_BLOCKS = 100


def sharechain_active(height):
    h = SHARECHAIN_ACTIVATION_HEIGHT
    return h is not None and height is not None and height >= h


def sharechain_phase(height):
    """'off' before activation, 'grace' during the soft window, 'hard' after."""
    h = SHARECHAIN_ACTIVATION_HEIGHT
    if h is None or height is None or height < h:
        return "off"
    if height < h + SHARECHAIN_GRACE_BLOCKS:
        return "grace"
    return "hard"


# The anchor-recency fix is itself a consensus change: it alters which payout a
# block must carry, so every node has to switch at the same height or the chain
# splits into two coins -- exactly what the comments above warn about. So it gets
# its own activation height and stays dormant (None-safe, off everywhere) until
# that block. Moved to 6200 after the first attempt's activation slipped past the
# live tip before miners had updated: setting it above the current height turns
# the rule back OFF on every node running this build, so an updated seed re-joins
# nodes still on the old build instead of splitting from them, and the rule then
# turns on cleanly at 6200 once the whole network is updated. While off, `fresh`
# is never passed and the payout is computed exactly as it is today.
SCHAIN_ANCHOR_ACTIVATION_HEIGHT = None


def anchor_rule_active(height):
    h = SCHAIN_ANCHOR_ACTIVATION_HEIGHT
    return h is not None and height is not None and height >= h


def fresh_anchor_hashes(chain_list, upto_hash, span=SCHAIN_ANCHOR_BLOCKS):
    """The hashes of the last `span` blocks up to and including the block named
    by `upto_hash`. A share whose block_prev is in this set was mined against
    current work. Returns None if that block isn't in the chain we hold -- deep
    re-validation of old history, where filtering is neither possible nor wanted
    (None means 'no filter', the pre-fix behaviour). Both the block builder and
    the validator derive this from the same agreed main chain ending at the same
    parent, so they compute an identical set and agree on the payout."""
    idx = None
    for i in range(len(chain_list) - 1, -1, -1):
        if chain_list[i].compute_hash() == upto_hash:
            idx = i
            break
    if idx is None:
        return None
    lo = max(0, idx - span + 1)
    return {b.compute_hash() for b in chain_list[lo:idx + 1]}


def block_payout_is_valid(reward_txs, share_chain, reward, height,
                          window=PPLNS_WINDOW, tip=None):
    """
    The forcing rule. Below the activation height it is a no-op (old validation
    stands, chain unchanged). At/after it, the block's reward transactions must
    match the canonical payout from the share-chain exactly -- same payees, same
    amounts. Anything else is rejected.
    """
    if not sharechain_active(height):
        return True
    expected = canonical_payout(share_chain, reward, window=window, tip=tip)
    got = {}
    for tx in reward_txs:
        if not isinstance(tx, dict):
            return False
        to, amt = tx.get("to"), tx.get("amount")
        if not isinstance(to, str) or not isinstance(amt, (int, float)):
            return False
        if to in got:
            return False                      # a payee listed twice
        got[to] = round(amt, 8)
    if set(got) != set(expected):
        return False                          # someone owed was left out, or
                                              # someone not owed was slipped in
    for a, amt in expected.items():
        if abs(got[a] - amt) > 1e-7:
            return False                      # right people, wrong amounts
    return True


def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


_chain_cache = {"tip": None, "body": b"[]"}
_chain_cache_lock = threading.Lock()


def _cached_chain_payload(node):
    """
    The chain as JSON bytes, re-encoded only when a new block arrives.

    Everything that syncs asks for this, so it is by far the hottest thing the
    node serves. Encoding it per request -- while holding the node's main lock
    -- was enough on its own to make a busy seed stop answering.
    """
    with node.lock:
        tip = node.chain.last_block.compute_hash()
        need = _chain_cache["tip"] != tip
        blocks = chain_to_list(node.chain) if need else None
    if not need:
        return _chain_cache["body"]
    body = json.dumps(blocks).encode()
    with _chain_cache_lock:
        _chain_cache["tip"] = tip
        _chain_cache["body"] = body
    return body


def chain_to_list(chain):
    return [{"index": b.index, "timestamp": b.timestamp, "transactions": b.transactions,
             "previous_hash": b.previous_hash, "nonce": b.nonce} for b in chain.chain]


def list_to_chain(data):
    chain = Blockchain()
    chain.chain = [Block(b["index"], b["transactions"], b["previous_hash"],
                         b["timestamp"], b["nonce"]) for b in data]
    return chain


def block_to_dict(block):
    return {"index": block.index, "timestamp": block.timestamp,
            "transactions": block.transactions,
            "previous_hash": block.previous_hash, "nonce": block.nonce}


def _check_block_content(transactions, prev_hash, share_target, height=None,
                         recent_tips=(), balances_before=None, share_chain=None,
                         schain_fresh=None):
    shares_entries = []
    rewards = []
    transfers = []
    has_version_tag = False
    for tx in transactions:
        if not isinstance(tx, dict):
            return False, 0.0
        t = tx.get("type")
        if t == "shares":
            shares_entries.append(tx)
        elif t == "reward":
            if not amount_is_sane(tx.get("amount"), allow_zero=True):
                return False, 0.0
            if not isinstance(tx.get("to"), str) or not tx["to"].startswith("SOSA"):
                return False, 0.0
            rewards.append(tx)
        elif t == "transfer":
            # Dormant until activation: below the activation height a transfer in
            # a block is invalid, exactly as it always was. This is the line that
            # keeps the live chain behaving identically until the switch is set.
            if not transfers_active(height):
                return False, 0.0
            if not transfer_is_valid(tx) or not transfer_work_is_valid(tx):
                return False, 0.0
            transfers.append(tx)
        elif t == "version":
            if tx.get("v", 0) >= 1:
                has_version_tag = True
        else:
            return False, 0.0

    # Transfers settle by chain order: check each against the balances that
    # exist just before this block -- no overspend, no double-spend. This block
    # is empty of transfers below activation, so this whole check is skipped and
    # nothing changes for the existing chain.
    if transfers:
        if balances_before is None:
            return False, 0.0        # cannot verify a spend without ledger state
        _bal = dict(balances_before)
        for tx in transfers:
            frm, to, amt = tx["from"], tx["to"], tx["amount"]
            if amt <= 0 or amt > _bal.get(frm, 0.0) + 1e-9:
                return False, 0.0
            _bal[frm] = round(_bal.get(frm, 0.0) - amt, 8)
            _bal[to] = round(_bal.get(to, 0.0) + amt, 8)

    if len(shares_entries) > 1:
        return False, 0.0

    counts = {}
    weights = {}          # difficulty-weighted work per address (fair-work payout)
    if shares_entries:
        lst = shares_entries[0].get("list", [])
        # At/after the fair-work flag day the block may legitimately carry more
        # shares (they're easier), so the cap widens then.
        _cap = FAIRWORK_MAX_SHARES if fairwork_active(height) else MAX_SHARES_PER_BLOCK
        if not isinstance(lst, list) or len(lst) > _cap:
            return False, 0.0
        seen = set()
        for s in lst:
            if not isinstance(s, dict):
                return False, 0.0
            addr, nonce = s.get("address"), s.get("nonce")
            if not isinstance(addr, str) or not addr.startswith("SOSA") \
                    or not isinstance(nonce, int):
                return False, 0.0
            # A share may name the tip it was mined against. Work done a moment
            # before someone else found a block is still work, and throwing it
            # away meant a fast miner kept whole rewards while everyone else's
            # effort vanished on timing alone. A share stays payable for a few
            # blocks, so nobody loses what they earned by being slightly late.
            # Shares with no tip named are read as belonging to this block's own
            # parent, which is exactly what every earlier block meant -- so the
            # whole existing chain still validates unchanged.
            at = s.get("prev", prev_hash)
            if not isinstance(at, str):
                return False, 0.0
            if at != prev_hash and at not in recent_tips:
                return False, 0.0
            if (addr, nonce, at) in seen:
                return False, 0.0
            seen.add((addr, nonce, at))
            _hv = int(share_hash(at, addr, nonce), 16)
            if _hv >= share_target:
                return False, 0.0
            counts[addr] = counts.get(addr, 0) + 1
            # difficulty weight: how far under target this share landed (min 1).
            # Only used by the fair-work payout; harmless to compute otherwise.
            weights[addr] = weights.get(addr, 0.0) + share_difficulty(hex(_hv), share_target)

    block_reward = round(sum(tx["amount"] for tx in rewards), 8)
    if rewards:
        # Collect what this block actually pays.
        got = {}
        for tx in rewards:
            if tx["to"] in got:
                return False, 0.0
            got[tx["to"]] = round(tx["amount"], 8)

        def _matches(expected):
            if set(got) != set(expected):
                return False
            for a, amt in expected.items():
                if abs(got[a] - amt) > 1e-7:
                    return False
            return True

        # The old rule: the reward splits across the shares carried IN the block.
        # At/after the fair-work flag day it splits by DIFFICULTY-WEIGHTED work
        # instead of raw share count, so every device is paid exactly for the work
        # it proved. Both builder and validator compute this identically from the
        # block's own shares, so updated nodes always agree.
        if fairwork_active(height):
            old_expected = split_amounts_weighted(block_reward, weights) if weights else None
        else:
            old_expected = split_amounts(block_reward, counts) if counts else None

        # The forced fair-payout: the split dictated by the SHARE-CHAIN, which no
        # single miner controls. Computed only when the rule is in force and we
        # actually hold the share-chain to derive it from.
        phase = sharechain_phase(height)
        canon = None
        if phase in ("grace", "hard") and share_chain is not None:
            canon = (canonical_payout_allwork(share_chain, block_reward,
                                              window=PPLNS_WINDOW, fresh=schain_fresh)
                     if allpay_active(height)
                     else canonical_payout(share_chain, block_reward,
                                           window=PPLNS_WINDOW, fresh=schain_fresh))

        def _recent_window():
            # the payout window the anti-freeze check reasons over. Once the
            # anchor rule is on it must follow the SAME recent tip the payout
            # does and count only recently-anchored shares -- otherwise it walks
            # the raw (possibly stale) tip, filters everything out, and both
            # fails to catch a hoarder AND could mis-flag a lone active miner.
            if share_chain is None:
                return []
            if schain_fresh is not None:
                tip = share_chain.best_recent_tip(schain_fresh)
                w = share_chain.tail(PPLNS_WINDOW, tip)
                return [s for s in w if s.get("block_prev") in schain_fresh]
            return share_chain.tail(PPLNS_WINDOW)

        if paylist_active(height):
            # PAYLIST: the reward must equal the split across the block's own
            # proof-of-work-verified share list. Every node reads that list from
            # the block and computes the identical split, so it's deterministic
            # (no fork from propagation lag) and inclusive -- everyone recorded
            # as having worked in this block is paid, nobody is skipped.
            ok_pay = (_matches(old_expected) if old_expected is not None
                      else len(got) <= 1)
            if not ok_pay:
                return False, 0.0
        elif phase == "hard":
            # The fair payout is ideal -- accept it outright.
            if canon and _matches(canon):
                pass
            else:
                # Do NOT freeze the chain when our share-chain and the block's
                # don't line up exactly. After a restart, or during normal
                # propagation lag, two nodes can hold slightly different share-
                # chains, and demanding an exact match rejected every block and
                # deadlocked the whole network. So here we enforce only the harm
                # that actually matters and is unambiguous: a block that pays a
                # SINGLE miner while our share-chain plainly shows several
                # distinct contributors in the window is hoarding, and dies.
                # Everything else keeps the chain moving.
                window = _recent_window()
                contributors = {s["address"] for s in window}
                if (len(window) >= SCHAIN_ENFORCE_MIN
                        and len(contributors) >= 2 and len(got) == 1):
                    return False, 0.0
        elif phase == "grace" and canon is not None:
            # Accept either the old or the fair payout, so nobody is stranded
            # while the update spreads.
            ok_old = (_matches(old_expected) if old_expected is not None
                      else len(rewards) <= 1)
            if not (_matches(canon) or ok_old):
                # same anti-freeze reasoning as hard: only stop blatant hoarding
                window = _recent_window()
                contributors = {s["address"] for s in window}
                if (len(window) >= SCHAIN_ENFORCE_MIN
                        and len(contributors) >= 2 and len(got) == 1):
                    return False, 0.0
        elif phase in ("grace", "hard"):
            # Rule in force but no share-chain handed to us: this is historical
            # re-validation (a deep check long after the fact). The canonical
            # split can't be reconstructed from pruned history, and fair blocks
            # won't match the old in-block split either, so neither can be
            # demanded here. Structure, duplicates and totals are still
            # enforced; the live network enforced the split when the block was
            # at the tip.
            pass
        else:
            # Rule off (or share-chain not available to us): original validation,
            # exactly as before -- the live chain is unchanged until activation.
            if counts:
                if not _matches(old_expected):
                    return False, 0.0
            else:
                if len(rewards) > 1:
                    return False, 0.0
    return True, block_reward


# Blocks whose expensive proofs this node has already checked, keyed by the
# block's own (cheap) hash. Re-running memory-hard work on a chain we have
# already accepted would make start-up take hours -- but the cheap structural
# checks below still run on every block every time, so a tampered old block
# still breaks the links and gets caught.
#
# A dict, not a set, so it stays insertion-ordered: at the cap we drop the OLDEST
# entries instead of wiping the whole thing. On a chain longer than the cap (a
# set wipe happened every time it filled -- about every two weeks at 60s blocks),
# the wipe forced a full re-verification storm; evicting the oldest keeps the
# recent tip verified, which is all that matters. Membership tests, iteration and
# sorted() all work on the keys exactly as they did on the set.
_verified_work = {}

# Only one background verification may run at a time, and it only looks at the
# most recent blocks. Older ones were checked when they arrived and now sit
# under a pile of later work; re-hashing them forever bought nothing and cost
# the miner most of its speed.
_verify_gate = threading.Semaphore(1)

# Only one push and one sync may be in flight at a time. Six different events --
# a block arriving, a share, a vote -- each used to start a fresh thread, and on
# a busy node they arrived faster than they finished. Threads climbed past sixty,
# every one holding connections and waiting on timeouts, memory grew, and the
# node ended up unable to answer anything while using no processor at all.
# Dropping a duplicate costs nothing: the work is idempotent and the regular
# three-second loop performs it again shortly anyway.
_push_gate = threading.Semaphore(1)
_sync_gate = threading.Semaphore(1)


def push_chain_once(node):
    if not _push_gate.acquire(blocking=False):
        return
    try:
        push_chain(node)
    except Exception:
        pass
    finally:
        _push_gate.release()


def sync_once(node):
    if not _sync_gate.acquire(blocking=False):
        return
    try:
        sync(node)
    except Exception:
        pass
    finally:
        _sync_gate.release()
VERIFY_DEPTH = 120
_VERIFIED_CAP = 20000


def _remember_verified(block_id):
    # Drop the oldest entries down to just under the cap, then record this one.
    # (Insertion order is preserved by dict, so next(iter(...)) is the oldest.)
    while len(_verified_work) >= _VERIFIED_CAP:
        _verified_work.pop(next(iter(_verified_work)), None)
    _verified_work[block_id] = True


def _tips_before(chain_list, index):
    """The hashes of the few blocks just before this one -- the payable window."""
    lo = max(0, index - 1 - SHARE_WINDOW)
    return {b.compute_hash() for b in chain_list[lo:max(0, index - 1)]}


def validate_full_chain(chain):
    if not chain.chain:
        return False
    if chain.chain[0].compute_hash() != _CANONICAL_GENESIS_HASH:
        return False
    # link integrity, timestamps and difficulty -- cheap, always checked in full
    if not chain.is_chain_valid(skip_work=_verified_work):
        return False
    targets = compute_targets(chain.chain)
    minted = 0.0
    running_bal = {}            # running ledger, used only to check transfers

    def _fold(block):
        # fold a block's effects into the running balance -- matches
        # compute_balances exactly, so both validators agree
        for tx in block.transactions:
            if not isinstance(tx, dict):
                continue
            ty = tx.get("type")
            if ty == "reward":
                running_bal[tx["to"]] = round(running_bal.get(tx["to"], 0.0)
                                              + tx.get("amount", 0.0), 8)
            elif ty == "transfer":
                running_bal[tx["from"]] = round(running_bal.get(tx["from"], 0.0)
                                                - tx.get("amount", 0.0), 8)
                running_bal[tx["to"]] = round(running_bal.get(tx["to"], 0.0)
                                              + tx.get("amount", 0.0), 8)

    for block in chain.chain:
        if block.index == 0:
            continue
        bid = block.compute_hash()
        has_transfer = any(isinstance(tx, dict) and tx.get("type") == "transfer"
                           for tx in block.transactions)
        if bid in _verified_work:
            # already re-done this block's work; still count its reward and fold
            for tx in block.transactions:
                if isinstance(tx, dict) and tx.get("type") == "reward":
                    minted += tx.get("amount", 0.0)
            _fold(block)
            continue
        # only pay the cost of a balances snapshot when a block actually carries
        # a transfer -- so below activation this is always None and nothing changes
        bb = dict(running_bal) if has_transfer else None
        ok, block_reward = _check_block_content(
            block.transactions, block.previous_hash,
            share_target_at(targets[block.index], block.index), height=block.index,
            recent_tips=_tips_before(chain.chain, block.index),
            balances_before=bb)
        if not ok:
            return False
        if block_reward > BLOCK_REWARD + 1e-6:
            return False
        minted += block_reward
        _fold(block)
        _remember_verified(bid)
    if minted > MAX_SUPPLY + 1e-6:
        return False
    return True


MTP_WINDOW = 11      # median-time-past window (last 11 blocks, like Bitcoin)


def median_time_past(chain_list, upto_index):
    """
    The median timestamp of the up-to-11 blocks ending just before `upto_index`.
    A new block's timestamp must be strictly greater than this. It is a PAST-only,
    fully deterministic bound -- no wall clock -- so every node computes the same
    value and none can disagree because its clock differs. It stops a miner from
    stamping a block with a backwards time to skew LWMA difficulty downward.
    """
    lo = max(0, upto_index - MTP_WINDOW)
    times = sorted(b.timestamp for b in chain_list[lo:upto_index])
    if not times:
        return None
    return times[len(times) // 2]


def timestamp_ok(chain_list, block):
    """v6 rule: block time must be above the median of the previous 11. Below the
    v6 flag day this always passes, so existing history is unaffected."""
    if not v6_active(block.index):
        return True
    mtp = median_time_past(chain_list, block.index)
    if mtp is None:
        return True
    return block.timestamp > mtp


def validate_new_block(chain, block, share_chain=None):
    if block.previous_hash != chain.last_block.compute_hash():
        return False
    if block.index != chain.last_block.index + 1:
        return False
    if not timestamp_ok(chain.chain, block):
        return False
    target = next_target(chain.chain)
    if int(block.pow_hash(), 16) >= target:
        return False
    has_transfer = any(isinstance(tx, dict) and tx.get("type") == "transfer"
                       for tx in block.transactions)
    bb = compute_balances(chain) if has_transfer else None
    # Anchor-recency set: the recent block hashes ending at this block's parent.
    # Only computed once the fix is active; below that it stays None and the
    # payout is validated exactly as before. Derived from the parent so the
    # builder (which built on that same parent) computes the identical set.
    schain_fresh = (fresh_anchor_hashes(chain.chain, block.previous_hash)
                    if anchor_rule_active(block.index) else None)
    ok, block_reward = _check_block_content(
        block.transactions, block.previous_hash,
        share_target_at(target, block.index),
        height=block.index,
        recent_tips=_tips_before(chain.chain + [block], block.index),
        balances_before=bb, share_chain=share_chain, schain_fresh=schain_fresh)
    if not ok:
        return False
    if block_reward > BLOCK_REWARD + 1e-6:
        return False
    if total_minted(chain) + block_reward > MAX_SUPPLY + 1e-6:
        return False
    return True


def _no_constants(_name):
    # JSON permits the bare tokens NaN, Infinity and -Infinity, and Python
    # parses them happily. They must never reach the ledger, so refuse them at
    # the door rather than trying to catch them at every later comparison.
    raise ValueError("non-finite numbers are not accepted")


def loads_strict(text):
    return json.loads(text, parse_constant=_no_constants)


def _chain_work(chain):
    """
    Total cumulative proof-of-work in a chain: the sum, over every block, of how
    many attempts that block's difficulty demands on average (MAX_TARGET/target).
    A harder block (smaller target) contributes more, so this measures real work
    done, not block count. Deterministic: every node derives the same targets
    from the same blocks and gets the same total.
    """
    targets = compute_targets(chain.chain)
    total = 0
    for t in targets:
        total += MAX_TARGET // max(1, t)
    return total


def is_better(candidate, current):
    lc, cc = len(candidate.chain), len(current.chain)
    # v6: heaviest chain wins. Both tips must be past the flag day, so a mixed
    # network still agrees by length below it and only switches to work-based
    # selection together, at the coordinated height. Below v6 this is exactly the
    # old length rule, so nothing changes for existing history.
    ctip = candidate.chain[-1].index if candidate.chain else -1
    utip = current.chain[-1].index if current.chain else -1
    if v6_active(ctip) and v6_active(utip):
        wc, wu = _chain_work(candidate), _chain_work(current)
        if wc != wu:
            return wc > wu
        # equal work -> lowest tip hash, so every node breaks the tie identically
        return candidate.chain[-1].compute_hash() < current.chain[-1].compute_hash()
    if lc != cc:
        return lc > cc
    return candidate.chain[-1].compute_hash() < current.chain[-1].compute_hash()


def _vote_core(v):
    return json.dumps({k: v[k] for k in
                      ("validator", "validator_pubkey", "tx_signature", "approve")},
                      sort_keys=True)


def make_vote(wallet, tx_signature, approve):
    v = {"validator": wallet.address(), "validator_pubkey": wallet.public_key_hex(),
         "tx_signature": tx_signature, "approve": bool(approve)}
    v["vote_signature"] = wallet.sign(_vote_core(v))
    return v


def vote_is_valid(v):
    try:
        if v["validator"] != _address_from_pubkey(v["validator_pubkey"]):
            return False
        return verify_signature(v["validator_pubkey"], _vote_core(v), v["vote_signature"])
    except Exception:
        return False


class Node:
    def __init__(self, port, wallet_password=None):
        self.port = port
        self.node_id = uuid.uuid4().hex[:8]
        self.my_url = f"http://{get_lan_ip()}:{port}"
        self.chain_file = f"chain_{port}.json"
        self.wallet_file = f"wallet_{port}.pem"
        self.peers_file = f"peers_{port}.json"
        self.peers_seen_file = f"peers_seen_{port}.json"
        self.transfers_file = f"transfers_{port}.json"
        self.validators_file = f"validators_{port}.json"

        # These must exist before the loaders below run: _load_chain checks
        # seed_only, and reading an attribute that did not exist yet threw an
        # error that a catch-all quietly swallowed -- which silently discarded
        # a perfectly good 267-block chain and started over from genesis.
        self.seed_only = False
        self.wallet_password = wallet_password
        self.no_upnp = False
        self.no_nostr = False

        # Cached /network summary. Recomputing it walks the whole chain, which is
        # cheap at a few hundred blocks and slow at tens of thousands. Every mint
        # page load used to trigger that full walk -- while holding the node lock,
        # so it also stalled mining. We now cache the result for a few seconds:
        # (built_at_timestamp, block_count_at_build, payload_dict).
        self._network_cache = None
        self._network_cache_lock = threading.Lock()
        # Incremental accumulator for the /network summary. Instead of walking the
        # whole chain on every rebuild (24s at 14k blocks), we keep running tallies
        # and fold in only the blocks added since last time. Reset if the chain
        # ever shrinks/reorgs (handled in the handler).
        self._net_acc = {"count": 0, "minted": 0.0,
                         "earned": {}, "won": {}}

        self.wallet = self._load_or_create_wallet()
        self._load_verified()
        self.chain = self._load_chain()
        self.peers = self._load_peers()
        # Re-entrant on purpose. A plain Lock is not: a thread that already
        # holds it and asks for it again waits for itself, forever. That is
        # exactly what happened when the mining loop called build_candidate()
        # from inside a locked section -- the miner froze holding the lock, and
        # every request and every sync then queued behind it. The node looked
        # completely dead while using no processor at all. RLock makes taking it
        # twice on one thread harmless, which removes the whole class of bug
        # rather than the one instance of it.
        self.lock = threading.RLock()

        self.registry = {self.wallet.address(): {"pubkey": self.wallet.public_key_hex()}}
        # When each validator was last heard from. Without this, "half the
        # stake must agree" meant half of every coin ever mined, including
        # coins belonging to people who have not run the software in days --
        # so a small holder could never move their own money. Nobody was
        # refusing; the votes simply could not arrive.
        self.seen_at = {self.wallet.address(): time.time()}

        self.transfers = {}

        self.votes = {}

        self.confirmed_log = []
        self.confirmed = set()

        self.mining = False
        # True once we've pulled the network's chain at least once. Mining refuses
        # to start before this when peers exist, so a fresh miner can't strike a
        # dead fork on its lone genesis block before it has caught up.
        self.has_synced = False
        self.mine_stats = {"start": None, "earned": 0.0, "blocks": 0}
        self.events = collections.deque(maxlen=40)
        # mining rewards are credited here; defaults to this node's own wallet,
        # but a dedicated miner can point it at any address (no keys needed)
        self.payout_address = self.wallet.address()
        self._last_push_len = 0
        self.warned_peers = set()
        self.reachable = False        # confirmed by a peer, never assumed
        self.public_url = None        # how the outside world sees us
        self.upnp_opened = False
        self.no_upnp = False
        self.no_nostr = False

        self.cur_shares = {"prev": None, "by": {}, "version": 0}
        self.recent_shares = {}   # tip_hash -> {address: {nonces}} for recent tips
        # The live share-chain: linked shares from every miner, the record the
        # forced fair-payout is computed from. Persisted to disk and reloaded on
        # start -- a restart used to wipe it to empty, and with the forcing rule
        # active that empty/desynced state deadlocked block production. Saving it
        # is what lets the rule stay ON safely across restarts.
        self.schain_file = f"schain_{port}.json"
        self.share_chain = ShareChain()
        self._load_share_chain()
        self.peer_misses = {}     # peer -> consecutive failed checks
        self.peer_seen = self._load_peer_seen()   # peer url -> last answered, so
                                  # a node that just briefly flickered still counts
                                  # as a way in instead of vanishing -- and this
                                  # survives a restart so the entry-point list does
                                  # not collapse to one machine on every reboot
        # How many cores to mine with.
        #
        # Half the machine by default. Taking all-but-one pinned people's CPUs at
        # 98% and made the miner unpleasant to leave running -- which matters
        # more than peak hashrate, because a miner someone turns off mines
        # nothing. Set SOS_THREADS, or pass --threads=, to choose your own.
        # (SOS_THREADS is exactly what a miner asked for, so it is what it is.)
        try:
            self.mine_threads = max(1, min(64, int(os.environ["SOS_THREADS"])))
        except (KeyError, ValueError):
            self.mine_threads = max(1, (os.cpu_count() or 2) // 2)
        self._load_validators()
        self._load_transfers()
        if self.peers:
            print(f"  Remembered {len(self.peers)} peer(s) from last time.")

    def _load_or_create_wallet(self):
        # Track whether this wallet is a brand-new one the user hasn't confirmed
        # through the app's onboarding yet. When it's fresh, the UI shows the
        # create/import welcome screen instead of dropping straight in -- so a
        # first launch asks the user what they want rather than silently minting
        # a wallet they didn't ask for.
        self.wallet_is_fresh = False
        if os.path.exists(self.wallet_file):
            # A locked wallet needs its password. Whoever is starting us decides
            # how to ask for it -- the desktop app pops a box, a server reads
            # SOSA_PASSWORD from its environment, and the console asks here.
            if Wallet.is_locked(self.wallet_file):
                pw = self.wallet_password or os.environ.get("SOSA_PASSWORD")
                if not pw and sys.stdin and sys.stdin.isatty():
                    import getpass
                    pw = getpass.getpass("  Wallet password: ")
                w = Wallet.load_from_file(self.wallet_file, password=pw)
            else:
                w = Wallet.load_from_file(self.wallet_file)
            print(f"  Loaded wallet: {w.address()}")
            if not w.has_phrase():
                print("  (this wallet predates recovery phrases -- it has no backup words.")
                print("   to get a recoverable wallet, make a new one and send your SOSA to it.)")
        else:
            # No wallet yet. Create a working one so the node can run, but mark
            # it FRESH and do NOT print the phrase here -- the app's onboarding
            # screen will either keep it (showing the phrase there) or replace it
            # via create/import. On a plain console start we still announce it.
            self.wallet_is_fresh = True
            try:
                w, phrase = Wallet.create_with_phrase()
                w.save_to_file(self.wallet_file)
                self._fresh_phrase = phrase
                if not (sys.stdin and sys.stdin.isatty()):
                    # launched by the app (no console prompt) -- stay quiet, let
                    # the UI handle onboarding
                    pass
                else:
                    print(f"  New wallet: {w.address()}")
                    print("\n  ================= WRITE THESE WORDS DOWN =================")
                    for i in range(0, len(phrase.split()), 6):
                        print("    " + " ".join(phrase.split()[i:i + 6]))
                    print("  These 17 words are the only way back to this wallet if you")
                    print("  lose this computer. Anyone who reads them owns your coins.")
                    print("  =========================================================\n")
            except Exception as e:
                w = Wallet(); w.save_to_file(self.wallet_file)
                self._fresh_phrase = None
                print(f"  New wallet: {w.address()}")
                print(f"  (no recovery phrase: {e})")
        return w

    def _load_chain(self):
        if not os.path.exists(self.chain_file):
            print("  No saved chain -- starting from genesis.")
            return Blockchain()
        try:
            with open(self.chain_file) as f:
                chain = list_to_chain(json.load(f))
            # Links only. This is our own chain, saved after we had already
            # checked each block as it arrived. Re-running the memory-hard proof
            # over every block here meant that once a node had a real chain, the
            # app spent minutes grinding before its window ever appeared -- it
            # looked like it would only ever open once. Editing the file on disk
            # still breaks the links and is caught immediately; the proof itself
            # is re-confirmed near the tip in the background.
            if chain.chain and chain.chain[0].compute_hash() == _CANONICAL_GENESIS_HASH \
                    and chain.is_chain_valid(links_only=True):
                print(f"  Loaded chain: {len(chain.chain)} blocks.")
                # A seed node trusts the chain it already checked block by block
                # as it arrived. Re-hashing the whole thing on every start is
                # what pinned the processor and made it stop answering; every
                # NEW block is still verified in full when it comes in.
                if not self.seed_only:
                    threading.Thread(target=self._verify_chain_background,
                                     args=(chain,), daemon=True).start()
                return chain
            print("  ! Saved chain did not pass its structure check.")
        except Exception as e:
            print(f"  ! Could not read the saved chain: {type(e).__name__}: {e}")
        print("  Saved chain invalid -- starting fresh.")
        return Blockchain()

    def _verify_chain_background(self, chain):
        """
        Re-confirm proof-of-work near the tip, one thread at a time.

        Two things made this ruinous before. Every reorg started another one of
        these, so on a busy network they stacked up -- each grinding memory-hard
        hashes through the whole chain -- and a miner's speed decayed steadily
        the longer it ran. And each pass walked all several hundred blocks, so
        it rarely finished, so it never saved its progress, so the next start
        did the whole thing again and the app looked frozen.

        Now: only one ever runs, it only looks at recent blocks (older ones were
        already checked when they arrived, and are buried under later work), and
        it writes down what it has confirmed as it goes.
        """
        if not _verify_gate.acquire(blocking=False):
            return          # one is already running; a second adds nothing
        try:
            blocks = chain.chain
            targets = compute_targets(blocks)
            start = max(1, len(blocks) - VERIFY_DEPTH)
            for i in range(start, len(blocks)):
                block = blocks[i]
                bid = block.compute_hash()
                if bid in _verified_work:
                    continue
                target = targets[i] if i < len(targets) else MAX_TARGET
                ok, _ = _check_block_content(
                    block.transactions, block.previous_hash,
                    share_target_at(target, block.index), height=block.index,
                    recent_tips=_tips_before(blocks, block.index))
                if not ok or int(block.pow_hash(), 16) >= target:
                    # Do NOT throw the chain away. A background check deciding
                    # to wipe everything back to genesis is far more damaging
                    # than whatever it found. Report it and stop; if the chain
                    # really is bad the network's longer one replaces it.
                    print(f"  ! Note: block {block.index} did not pass the deep "
                          f"check on this build. Keeping the chain.")
                    return
                _remember_verified(bid)
                time.sleep(0.25)      # never take priority over mining
            self._save_verified()
        except Exception:
            pass
        finally:
            _verify_gate.release()

    def _verified_file(self):
        return f"verified_{self.port}.json"

    def _save_verified(self):
        try:
            with open(self._verified_file(), "w") as f:
                json.dump(sorted(_verified_work), f)
        except Exception:
            pass

    def _load_verified(self):
        try:
            if os.path.exists(self._verified_file()):
                with open(self._verified_file()) as f:
                    for h in json.load(f):
                        if isinstance(h, str):
                            _verified_work[h] = True
        except Exception:
            pass

    def save_chain(self):
        with open(self.chain_file, "w") as f:
            json.dump(chain_to_list(self.chain), f)

    def save_share_chain(self):
        """Persist the share-chain so a restart doesn't wipe it. Best-effort:
        a failed save never interrupts the node."""
        try:
            with self.lock:
                snap = self.share_chain.snapshot()
            tmp = self.schain_file + ".tmp"
            with open(tmp, "w") as f:
                json.dump(snap, f)
            os.replace(tmp, self.schain_file)   # atomic: never a half-written file
        except Exception:
            pass

    def _load_share_chain(self):
        if not os.path.exists(self.schain_file):
            return
        try:
            with open(self.schain_file) as f:
                saved = json.load(f)
            n = self.share_chain.restore(saved)
            if n:
                print(f"  Loaded share-chain: {n} shares.")
        except Exception:
            pass

    def _load_peers(self):
        if not os.path.exists(self.peers_file):
            return set()
        try:
            with open(self.peers_file) as f:
                saved = set(json.load(f))
            saved.discard(self.my_url)
            # Throw away other people's home-network addresses. They were saved
            # before we started filtering them, they can never be reached from
            # here, and re-dialling two dozen of them on every cycle was quietly
            # eating most of the processor.
            keep = {p for p in saved if is_public_url(p)}
            dropped = len(saved) - len(keep)
            if dropped:
                print(f"  Dropped {dropped} unreachable address(es) from the peer list.")
            return keep
        except Exception:
            return set()

    def save_peers(self):
        try:
            with open(self.peers_file, "w") as f:
                json.dump(sorted(self.peers), f)
        except Exception:
            pass
        # Persist last-answered times too, so the grace window that keeps a
        # briefly-flickering node listed as a way in survives a restart -- this
        # is what stops the entry-point list collapsing to one machine on reboot.
        try:
            fresh = {u: t for u, t in self.peer_seen.items()
                     if is_public_url(u)}
            with open(self.peers_seen_file, "w") as f:
                json.dump(fresh, f)
        except Exception:
            pass

    def _load_peer_seen(self):
        if not os.path.exists(self.peers_seen_file):
            return {}
        try:
            with open(self.peers_seen_file) as f:
                saved = json.load(f)
            if not isinstance(saved, dict):
                return {}
            return {u: float(t) for u, t in saved.items()
                    if isinstance(u, str) and is_public_url(u)}
        except Exception:
            return {}

    def _load_validators(self):
        if os.path.exists(self.validators_file):
            try:
                with open(self.validators_file) as f:
                    saved = json.load(f)
                for addr, info in saved.items():
                    self.registry.setdefault(addr, info)
            except Exception:
                pass

    def save_validators(self):
        try:
            with open(self.validators_file, "w") as f:
                json.dump(self.registry, f)
        except Exception:
            pass

    def _load_transfers(self):
        if not os.path.exists(self.transfers_file):
            return
        try:
            with open(self.transfers_file) as f:
                log = json.load(f)
        except Exception:
            return
        kept = 0
        balances_running = compute_balances(self.chain)   # chain truth; kept transfers applied as we go
        # Any transfer that already lives in a block is settled by the chain, so
        # the chain balance above already includes it. Loading it AGAIN from the
        # old vote-log would count it twice and inflate the balance (the "app
        # shows more than the chain" bug). Gather on-chain transfer signatures so
        # we can skip those log entries entirely -- so no user has to delete files.
        on_chain_sigs = set()
        for b in self.chain.chain:
            for t in b.transactions:
                if isinstance(t, dict) and t.get("type") == "transfer":
                    s = t.get("signature")
                    if s:
                        on_chain_sigs.add(s)
        for entry in log:
            tx, votes = entry.get("tx", {}), entry.get("votes", {})
            sig = tx.get("signature")
            if sig in on_chain_sigs:
                # already settled on-chain -> mark confirmed but DON'T re-apply
                self.confirmed.add(sig)
                continue
            if not sig or sig in self.confirmed or not transfer_is_valid(tx):
                continue
            if not all(vote_is_valid(v) for v in votes.values()):
                continue
            good = {a: v for a, v in votes.items()
                    if v.get("tx_signature") == sig and v.get("validator") == a}
            # A transfer moves only the SENDER'S OWN coins and is cryptographically
            # signed by that sender (verified by transfer_is_valid above), so the
            # signature -- not a re-run of the old live stake vote against today's
            # balances -- is the real authorization. The previous check re-required
            # the approving voters to still hold >50% of ALL network stake on every
            # restart; almost no ordinary sender does, so it silently dropped
            # confirmed transfers and REVERTED real payments on reboot. Keep a
            # previously-confirmed transfer if it still verifies (checked above) and
            # the sender can still afford it against the chain plus everything kept
            # so far. A tampered entry can't slip through -- transfer_is_valid would
            # have rejected it, because changing any field breaks the signature.
            if balances_running.get(tx["from"], 0.0) + 1e-9 < tx["amount"]:
                continue                      # sender can't afford it now -> skip
            balances_running[tx["from"]] = round(balances_running.get(tx["from"], 0.0) - tx["amount"], 8)
            balances_running[tx["to"]]   = round(balances_running.get(tx["to"], 0.0) + tx["amount"], 8)
            self.transfers[sig] = tx
            self.votes[sig] = dict(good)
            self.confirmed_log.append({"tx": tx, "votes": dict(good)})
            self.confirmed.add(sig)
            kept += 1
        if kept:
            print(f"  Loaded {kept} confirmed transfer(s).")

    def save_transfers(self):
        try:
            with open(self.transfers_file, "w") as f:
                json.dump(self.confirmed_log, f)
        except Exception:
            pass

    def _ensure_share_height(self):
        tip = self.chain.last_block.compute_hash()
        if self.cur_shares.get("prev") != tip:
            # A new tip. Keep the previous tip's shares around briefly instead
            # of discarding them -- shares from slower miners are often still in
            # flight when a block lands, and dropping them is exactly what let a
            # single fast miner take every reward. They stay claimable for the
            # next couple of blocks, then age out.
            old = self.cur_shares
            hist = self.recent_shares
            if old.get("prev") and old.get("by"):
                hist[old["prev"]] = old["by"]
                # Keep shares for exactly as long as they stay payable. The
                # payable window is SHARE_WINDOW blocks, so a share mined that
                # many tips back can still legitimately go into a block -- but
                # only if we still have it. Retaining fewer tips than the window
                # threw away work that was still owed payment, which stiffed
                # slower miners on valid shares. Retention now tracks the window.
                while len(hist) > SHARE_WINDOW:
                    hist.pop(next(iter(hist)))
            self.cur_shares = {"prev": tip, "by": {}, "version": 0}

    def _add_share(self, address, nonce):
        self._ensure_share_height()
        nonces = self.cur_shares["by"].setdefault(address, set())
        if nonce in nonces:
            return False
        nonces.add(nonce)
        self.cur_shares["version"] += 1
        return True

    def get_balances(self):
        balances = compute_balances(self.chain)
        # Transfers now settle ON-CHAIN (in blocks), so compute_balances already
        # includes every transfer that made it into a block. The confirmed_log is
        # the OLD vote-settled record; applying it on top would count any transfer
        # that is BOTH vote-confirmed AND on-chain twice -- which is exactly the
        # "app balance higher than the chain" drift. reconcile_chain_transfers
        # prunes the log, but only scans recent blocks, so a transfer buried deep
        # could linger in the log and be double-counted. Guard it here: skip any
        # log entry whose transfer is already in the chain.
        on_chain_sigs = set()
        for b in self.chain.chain:
            for tx in b.transactions:
                if isinstance(tx, dict) and tx.get("type") == "transfer":
                    s = tx.get("signature")
                    if s:
                        on_chain_sigs.add(s)
        for entry in self.confirmed_log:
            tx = entry["tx"]
            if tx.get("signature") in on_chain_sigs:
                continue                      # already counted by the chain
            balances[tx["from"]] = balances.get(tx["from"], 0) - tx["amount"]
            balances[tx["to"]] = balances.get(tx["to"], 0) + tx["amount"]
        return {a: round(b, 8) for a, b in balances.items()}

    def all_stake(self, balances=None):
        """
        Every registered holder's stake, awake or not.

        Used when judging a transfer other nodes have already settled. Live
        voting rightly asks only those present -- but checking somebody else's
        finished decision must not, or a node with no stake of its own (a seed
        never mines) finds the total is zero, refuses to adopt anything, and
        shows a transfer as pending for ever while everyone else has moved on.
        """
        balances = balances if balances is not None else self.get_balances()
        return sum(max(balances.get(a, 0), 0.0) for a in self.registry)

    def total_stake(self, balances=None):
        """
        The stake that is actually online and able to vote.

        Counting everyone who ever held a coin made transfers impossible the
        moment the large holders closed their wallets: a majority of all coins
        can never be reached if most of those coins are asleep. Only stake that
        has been heard from recently is asked to agree -- which is what
        "confirmed by the holders who are online" was always meant to mean.
        """
        balances = balances if balances is not None else self.get_balances()
        cutoff = time.time() - ACTIVE_VALIDATOR_WINDOW
        live = [a for a in self.registry if self.seen_at.get(a, 0) >= cutoff]
        if not live:
            live = [self.wallet.address()]
        return sum(max(balances.get(a, 0), 0.0) for a in live)

    def _committed_outgoing(self, addr, excluding_sig):
        total = 0.0
        me = self.wallet.address()
        for sig, tx in self.transfers.items():
            if sig == excluding_sig or sig in self.confirmed:
                continue
            if tx.get("from") != addr:
                continue
            mine = self.votes.get(sig, {}).get(me)
            if mine and mine.get("approve"):
                total += tx.get("amount", 0)
        return total

    def judge(self, tx):
        if not transfer_is_valid(tx):
            return False
        sig = tx.get("signature")
        if sig in self.confirmed:
            return False
        amt = tx.get("amount", 0)
        if amt <= 0:
            return False
        balances = self.get_balances()
        available = balances.get(tx["from"], 0) - self._committed_outgoing(tx["from"], sig)
        return available + 1e-9 >= amt

    def maybe_confirm(self, sig):
        if sig in self.confirmed or sig not in self.transfers:
            return False
        balances = self.get_balances()
        total = self.total_stake(balances)
        if total <= 0:
            return False
        yes = 0.0
        cutoff = time.time() - ACTIVE_VALIDATOR_WINDOW
        for addr, vote in self.votes.get(sig, {}).items():
            if (vote.get("approve") and addr in self.registry
                    and self.seen_at.get(addr, 0) >= cutoff):
                yes += max(balances.get(addr, 0), 0.0)
        if yes * 2 > total:
            tx = self.transfers[sig]
            self.confirmed_log.append({"tx": tx, "votes": dict(self.votes.get(sig, {}))})
            self.confirmed.add(sig)
            self.save_transfers()
            return True
        return False

    def retally(self):
        newly = []
        for sig in list(self.transfers):
            if sig not in self.confirmed and self.maybe_confirm(sig):
                newly.append(sig)
        return newly


def post_json(url, obj, timeout=2):
    try:
        data = json.dumps(obj).encode()
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return loads_strict(r.read())
    except Exception:
        return None


def get_json(url, timeout=3):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return loads_strict(r.read())
    except Exception:
        return None


# A single small pool for all outbound gossip/sync, so bursts of network
# activity cannot each spawn their own thread and pile up toward the OS limit.
_out_pool = ThreadPoolExecutor(max_workers=20, thread_name_prefix="sos-out")


def gossip(node, path, obj):
    for peer in list(node.peers):
        try:
            _out_pool.submit(post_json, peer.rstrip("/") + path, obj)
        except Exception:
            pass


def add_event(node, text):
    node.events.appendleft(f"{time.strftime('%H:%M:%S')}  {text}")


def announce_confirm(node, sig):
    tx = node.transfers.get(sig, {})
    add_event(node, f"confirmed {tx.get('amount')} SOSA  "
                    f"{tx.get('from', '?')[:10]}... -> {tx.get('to', '?')[:10]}...")
    print(f"\n  [confirmed] {tx.get('amount')} SOSA  "
          f"{tx.get('from', '?')[:14]}... -> {tx.get('to', '?')[:14]}...  "
          f"(feeless, by stake vote)\nsosa:{node.port}> ", end="", flush=True)


def cast_vote(node, tx):
    with node.lock:
        me = node.wallet.address()
        table = node.votes.setdefault(tx["signature"], {})
        prev = table.get(me)
        approve = node.judge(tx)
        if prev is not None and (prev.get("approve") or not approve):
            return
        vote = make_vote(node.wallet, tx["signature"], approve)
        table[me] = vote
        confirmed_now = node.maybe_confirm(tx["signature"])
    gossip(node, "/vote", vote)
    if confirmed_now:
        announce_confirm(node, tx["signature"])


def revote_pending(node):
    # At the coordinated on-chain flag day this loop stands down for good:
    # pending transfers wait for a miner to carry them into a block instead of
    # being vote-confirmed into the fragile side-cache. Gated on the FUTURE
    # shared height (not the long-past 4500) so every node switches together --
    # switching alone would double-count transfers against nodes still voting.
    if transfers_onchain_only(len(node.chain.chain)):
        return
    with node.lock:
        pending = [tx for sig, tx in node.transfers.items()
                   if sig not in node.confirmed]
    for tx in pending:
        cast_vote(node, tx)


def reconcile_chain_transfers(node):
    # A transfer that now lives in a block is SETTLED ON-CHAIN. Mark it confirmed
    # so the block-builder won't try to add it again, drop it from the pending
    # pool, and remove any stale vote-cache copy of it so balances (chain +
    # cache) can never count the same transfer twice. Only the recent tail is
    # scanned: a pending transfer is mined within a block or two of being sent,
    # and blocks are ~60s apart while this runs every few seconds, so settlement
    # is always caught long before the next block could re-include it.
    need_save = False
    with node.lock:
        on_chain = set()
        for b in node.chain.chain[-64:]:
            for tx in b.transactions:
                if isinstance(tx, dict) and tx.get("type") == "transfer":
                    sig = tx.get("signature")
                    if sig:
                        on_chain.add(sig)
        if on_chain:
            for sig in on_chain:
                if sig not in node.confirmed:
                    node.confirmed.add(sig); need_save = True
                if node.transfers.pop(sig, None) is not None:
                    need_save = True
            before = len(node.confirmed_log)
            node.confirmed_log = [e for e in node.confirmed_log
                                  if e.get("tx", {}).get("signature") not in on_chain]
            if len(node.confirmed_log) != before:
                need_save = True
    if need_save:
        node.save_transfers()


def api_summary(node):
    with node.lock:
        balances = node.get_balances()
        me = node.wallet.address()
        total = node.total_stake(balances)
        pend = [(s, t) for s, t in node.transfers.items() if s not in node.confirmed]

        def yes_pct(sig):
            yes = sum(max(balances.get(a, 0), 0.0)
                      for a, v in node.votes.get(sig, {}).items()
                      if v.get("approve") and a in node.registry)
            return round((100 * yes / total) if total > 0 else 0.0)

        pend_out = sum(t.get("amount", 0) for _, t in pend if t.get("from") == me)
        holders = [{"address": a, "balance": round(b, 8),
                    "pct": round(100 * b / total, 1) if total > 0 else 0.0,
                    "me": a == me}
                   for a, b in sorted(balances.items(), key=lambda kv: -kv[1])
                   if b > 1e-9][:8]
        pending = [{"amount": t.get("amount"), "frm": t.get("from", "?"),
                    "to": t.get("to", "?"), "yes": yes_pct(s)}
                   for s, t in pend[:6]]
        st = node.mine_stats
        elapsed = (time.time() - st["start"]) if (node.mining and st["start"]) else 0
        rate = round(st["earned"] / elapsed * 3600, 1) if elapsed > 1 else 0.0
        # Honest sync health for the app: are we actually on the network's tip,
        # still catching up, or islanded? A node that has adopted from a peer
        # recently (or has no peers to compare against yet) is "synced"; one that
        # is mining but hasn't heard a better tip in a while is "checking".
        now = time.time()
        last_adopt = getattr(node, "_last_peer_adopt", 0)
        has_peers = len(node.peers) > 0
        if not has_peers:
            sync_state = "finding"          # no peers yet
        elif getattr(node, "has_synced", False):
            sync_state = "synced"
        else:
            sync_state = "syncing"
        return {"address": me,
                "has_wallet": not getattr(node, "wallet_is_fresh", False),
                "synced": (getattr(node, "has_synced", False) or not has_peers),
                "sync_state": sync_state,
                "reachable": bool(getattr(node, "reachable", False)),
                "public_url": getattr(node, "public_url", None),
                "version": NODE_VERSION,
                "balance": round(balances.get(me, 0), 8),
                "available": round(balances.get(me, 0) - pend_out, 8),
                "blocks": len(node.chain.chain),
                "minted": round(total_minted(node.chain), 4),
                "max_supply": MAX_SUPPLY,
                "validators": len(node.registry),
                "total_stake": round(total, 8),
                "peers": sorted(node.peers),
                "mining": node.mining,
                "rate": rate,
                "session_earned": round(st["earned"], 6),
                "confirmed": len(node.confirmed),
                "pending": pending,
                "holders": holders,
                "events": list(node.events)}


DASHBOARD_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sosaiem Node</title>
<style>
:root{--bg:#0b1020;--card:#131a2f;--edge:#1f2a4a;--ink:#e8ecf8;--dim:#8b96b8;--teal:#4fd1c5;--gold:#f6c453;--red:#ef6b6b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1060px;margin:0 auto;padding:22px}
h1{font-size:22px;margin:0}h1 span{color:var(--teal)}
.sub{color:var(--dim);font-size:13px;margin:2px 0 18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--edge);border-radius:14px;padding:16px}
.card h2{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--dim);margin:0 0 10px}
.big{font-size:32px;font-weight:700}.big small{font-size:15px;color:var(--dim);font-weight:400}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all;color:var(--dim)}
button{background:var(--teal);color:#06231f;border:0;border-radius:9px;padding:9px 14px;font-weight:700;cursor:pointer}
button.off{background:var(--edge);color:var(--ink)}
input{width:100%;background:#0d1428;border:1px solid var(--edge);border-radius:9px;color:var(--ink);padding:9px 11px;margin:4px 0;font-size:14px}
.row{display:flex;gap:8px;align-items:center;justify-content:space-between}
.bar{height:7px;background:var(--edge);border-radius:5px;overflow:hidden;margin-top:5px}
.bar i{display:block;height:100%;background:var(--teal)}
.feed{max-height:230px;overflow:auto;font-family:ui-monospace,Consolas,monospace;font-size:12px}
.feed div{padding:3px 0;border-bottom:1px dashed var(--edge);color:var(--dim)}
table{width:100%;border-collapse:collapse;font-size:13px}td{padding:5px 4px;border-bottom:1px solid var(--edge)}
.tag{font-size:11px;color:var(--gold)}.ok{color:var(--teal)}.err{color:var(--red)}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--dim);margin-right:7px}
.dot.on{background:var(--gold);box-shadow:0 0 8px var(--gold)}
</style></head><body><div class="wrap">
<h1>SOSAIEM <span>&#9670;</span> society's coin</h1>
<div class="sub">post-quantum &middot; feeless transfers by stake vote &middot; pool-smooth mining with no pool boss &mdash; served by your own node</div>
<div class="grid">
<div class="card"><h2>My wallet</h2>
<div class="big" id="bal">&ndash;</div>
<div id="avail" class="sub"></div>
<div class="mono" id="addr"></div>
<div style="margin-top:8px"><button onclick="copyAddr()">copy address</button></div></div>
<div class="card"><h2>Mining</h2>
<div class="row"><div><span class="dot" id="mdot"></span><b id="mstate">&ndash;</b><div class="sub" id="mrate"></div></div>
<button id="mbtn" onclick="toggleMine()">&hellip;</button></div>
<div class="sub" style="margin-top:10px">~100 SOSA/hour network-wide, split by proven work-shares. Every active miner earns a slice of every block.</div></div>
<div class="card"><h2>Send SOSA (feeless)</h2>
<input id="sto" placeholder="SOSA... address">
<input id="samt" placeholder="amount" type="number" step="any">
<div class="row"><button onclick="doSend()">send</button><span id="smsg" class="sub"></span></div></div>
<div class="card"><h2>Network</h2>
<table><tr><td>blocks</td><td id="nblocks"></td></tr>
<tr><td>minted</td><td id="nmint"></td></tr>
<tr><td>validators known</td><td id="nvals"></td></tr>
<tr><td>total stake</td><td id="nstake"></td></tr>
<tr><td>peers</td><td id="npeers" class="mono"></td></tr></table>
<div class="bar"><i id="supbar" style="width:0%"></i></div>
<div class="sub" id="suplbl"></div></div>
<div class="card"><h2>Awaiting votes</h2><div id="pend" class="sub">none &mdash; all clear</div></div>
<div class="card"><h2>Holders</h2><table id="hold"></table></div>
<div class="card" style="grid-column:1/-1"><h2>Live feed</h2><div class="feed" id="feed"></div></div>
</div></div>
<script>
let S=null;
async function poll(){try{const r=await fetch('/api/summary');S=await r.json();render();}catch(e){}}
function esc(s){return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function render(){
 bal.innerHTML=S.balance.toFixed(6)+' <small>SOSA</small>';
 avail.textContent=(S.available<S.balance-1e-9)?('available: '+S.available.toFixed(6)+' (rest awaiting votes)'):'your balance is also your voting weight';
 addr.textContent=S.address;
 mdot.className='dot'+(S.mining?' on':'');mstate.textContent=S.mining?'mining':'idle';
 mrate.textContent=S.mining?('~'+S.rate+' SOSA/hour \\u00b7 session '+S.session_earned):'';
 mbtn.textContent=S.mining?'stop mining':'start mining';mbtn.className=S.mining?'off':'';
 nblocks.textContent=S.blocks;nmint.textContent=S.minted+' / '+S.max_supply;
 nvals.textContent=S.validators;nstake.textContent=S.total_stake;
 npeers.textContent=S.peers.length?S.peers.join('  '):'none yet';
 const pct=100*S.minted/S.max_supply;supbar.style.width=Math.max(pct,0.4)+'%';
 suplbl.textContent=pct.toFixed(4)+'% of all SOSA minted';
 pend.innerHTML=S.pending.length?S.pending.map(p=>'<div style="margin:6px 0"><b>'+p.amount+'</b> SOSA '+esc(p.frm.slice(0,10))+'&hellip; &rarr; '+esc(p.to.slice(0,10))+'&hellip;<div class="bar"><i style="width:'+Math.min(p.yes,100)+'%"></i></div><span class="tag">YES: '+p.yes+'% of stake (needs &gt;50%)</span></div>').join(''):'none &mdash; all clear';
 hold.innerHTML=S.holders.map(h=>'<tr><td class="mono">'+esc(h.address.slice(0,18))+'&hellip;'+(h.me?' <span class="tag">&larr; me</span>':'')+'</td><td>'+h.balance+'</td><td>'+h.pct+'%</td></tr>').join('');
 feed.innerHTML=S.events.length?S.events.map(e=>'<div>'+esc(e)+'</div>').join(''):'<div>waiting for activity&hellip;</div>';
}
async function toggleMine(){await fetch('/api/mine',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({on:!S.mining})});poll();}
async function doSend(){smsg.textContent='\\u2026';try{const r=await fetch('/api/send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({to:sto.value.trim(),amount:parseFloat(samt.value)})});const j=await r.json();smsg.textContent=j.message;smsg.className=j.ok?'sub ok':'sub err';if(j.ok){sto.value='';samt.value='';}}catch(e){smsg.textContent='error';smsg.className='sub err';}poll();}
function copyAddr(){navigator.clipboard.writeText(S.address);}
poll();setInterval(poll,2000);
</script></body></html>"""


def make_handler(node):
    class H(BaseHTTPRequestHandler):
        def _json(self, obj, code=200):
            try:
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                pass

        def _json_raw(self, body, code=200):
            """Send already-encoded JSON bytes without re-encoding them."""
            try:
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                pass

        def _read(self, cap=MAX_BODY_DEFAULT):
            n = int(self.headers.get("Content-Length", 0))
            if n > cap:
                raise ValueError("request body too large")
            return loads_strict(self.rfile.read(min(n, cap)))

        def _local(self):
            return self.client_address[0] in ("127.0.0.1", "::1")

        def _gate(self):
            # localhost (the owner's own wallet UI) is never throttled
            if self._local():
                return True
            if not rate_allowed(self.client_address[0]):
                self._json({"error": "rate limited"}, 429)
                return False
            return True

        def do_GET(self):
            if not self._gate():
                return
            self.note_inbound()
            if self.path in ("/", "/dashboard"):
                if not self._local():
                    self._json({"error": "the wallet dashboard answers only on "
                                         "the node's own computer (localhost)"}, 403)
                    return
                try:
                    # Prefer the modern wallet UI shipped alongside the node
                    # (wallet_ui.html); fall back to the built-in dashboard so
                    # the node still works on its own.
                    html = DASHBOARD_HTML
                    try:
                        # Look for the modern UI next to this file, and also in the
                        # PyInstaller bundle dir (sys._MEIPASS) so the single .exe
                        # finds its embedded wallet_ui.html.
                        _dirs = [os.path.dirname(os.path.abspath(__file__))]
                        _mei = getattr(sys, "_MEIPASS", None)
                        if _mei:
                            _dirs.insert(0, _mei)
                        for _d in _dirs:
                            _ui = os.path.join(_d, "wallet_ui.html")
                            if os.path.exists(_ui):
                                with open(_ui, encoding="utf-8") as _f:
                                    html = _f.read()
                                break
                    except Exception:
                        pass
                    body = html.encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                    pass
            elif self.path == "/api/summary":
                if not self._local():
                    self._json({"error": "localhost-only"}, 403); return
                self._json(api_summary(node))
            elif self.path == "/seeds":
                # Ways into the network, as far as this node knows. Any node can
                # answer this, so a newcomer who reaches one machine immediately
                # learns about many -- nobody has to maintain a list by hand.
                self._json({"seeds": good_seeds(node), "from": node.public_url or None})

            elif self.path == "/peers":
                with node.lock:
                    # Only offer ourselves as a way in if the outside world can
                    # actually get here. Handing newcomers an address that
                    # silently fails is worse than handing them nothing.
                    known = set(node.peers)
                    if node.reachable and node.public_url:
                        known.add(node.public_url)
                    self._json({"peers": sorted(known)})

            elif self.path.startswith("/reachme"):
                # A peer is asking whether we can see it. We only ever try the
                # address it is calling from, never one it names -- so this
                # cannot be used to make us knock on somebody else's door.
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                try:
                    p = int(q.get("port", ["0"])[0])
                except ValueError:
                    p = 0
                if not (1 <= p <= 65535):
                    self._json({"error": "bad port"}, 400); return
                who = self.client_address[0]
                seen = False
                try:
                    with urllib.request.urlopen(f"http://{who}:{p}/info", timeout=4) as r:
                        seen = (loads_strict(r.read()).get("genesis")
                                == _CANONICAL_GENESIS_HASH)
                except Exception:
                    seen = False
                self._json({"reachable": seen, "seen_as": who})
            elif self.path == "/chain" or self.path.startswith("/chain?"):
                # Plain /chain hands out the cached full-chain bytes (hottest
                # endpoint; encoded once per new block, not per request).
                # ?from=N returns ONLY blocks from index N onward, so a miner a
                # few blocks behind pulls a few KB instead of the whole multi-MB
                # chain -- which is what kept pull-only miners trailing the tip.
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                frm = q.get("from", [None])[0]
                if frm is not None:
                    try:
                        n = max(0, int(frm))
                    except ValueError:
                        n = 0
                    with node.lock:
                        part = [block_to_dict(b) for b in node.chain.chain[n:]]
                    self._json(part)
                else:
                    self._json_raw(_cached_chain_payload(node))
            elif self.path == "/state":
                with node.lock:
                    cut = time.time() - ACTIVE_VALIDATOR_WINDOW
                    self._json({"registry": node.registry,
                                "live": [a for a, t in node.seen_at.items() if t >= cut],
                                "log": node.confirmed_log,
                                "url": node.public_url or node.my_url})
            elif self.path == "/info":
                with node.lock:
                    self._json({"blocks": len(node.chain.chain),
                                "confirmed": len(node.confirmed),
                                "last_hash": node.chain.last_block.compute_hash(),
                                "protocol": PROTOCOL_VERSION,
                                "version": NODE_VERSION,
                                "synced": bool(getattr(node, "has_synced", False)),
                                "watchdog_resyncs": getattr(node, "watchdog_resyncs", 0),
                                "genesis": _CANONICAL_GENESIS_HASH})
            elif self.path == "/schain_tip":
                # The share-chain's current tip, so a peer can tell whether it is
                # behind and needs to pull the run of shares it is missing.
                with node.lock:
                    sc = node.share_chain
                    tip = sc.tip
                    self._json({
                        "tip": tip,
                        "height": sc.height.get(tip, 0) if tip else 0,
                        "cum": sc.cum.get(tip, 0) if tip else 0,
                        "count": len(sc.shares),
                    })
            elif self.path.startswith("/schain_shares"):
                # Serve the recent run of share-chain shares, oldest-first, so a
                # node that fell behind can rejoin the same share-chain. Oldest-
                # first matters: each share's parent must arrive before it.
                with node.lock:
                    run = node.share_chain.tail(SHARECHAIN_KEEP)
                self._json({"shares": run})
                return                       # BUGFIX: was falling through into a
                                             # second response, breaking share pull

            elif self.path == "/network":
                # Compact public summary for the live mint page.
                #
                # The tallies (minted, per-miner earnings, blocks won) are built
                # INCREMENTALLY: we remember how far we've counted and, on each
                # rebuild, fold in only the blocks added since -- instead of
                # walking all ~14k+ blocks every time (which took ~24s and made
                # the page hang). A short cache still absorbs bursts of requests.
                # If the chain ever shrinks (a reorg), we reset and recount once.
                NETWORK_CACHE_TTL = 3.0
                now = time.time()
                cached = node._network_cache
                with node.lock:
                    height = len(node.chain.chain)
                if (cached is not None
                        and cached[0] is not None
                        and (now - cached[0]) < NETWORK_CACHE_TTL
                        and cached[1] == height):
                    self._json(cached[2])       # serve the cached payload
                else:
                    with node.lock:
                        blocks = list(node.chain.chain)
                    acc = node._net_acc
                    n = len(blocks)
                    # Reset the accumulator if the chain shrank or diverged.
                    if acc["count"] > n:
                        acc = {"count": 0, "minted": 0.0, "earned": {}, "won": {}}
                    # Fold in only the NEW blocks since we last counted.
                    earned = acc["earned"]
                    won = acc["won"]
                    minted = acc["minted"]
                    for b in blocks[acc["count"]:]:
                        if b.index == 0:
                            continue
                        for tx in b.transactions:
                            if isinstance(tx, dict) and tx.get("type") == "reward":
                                a = tx.get("to")
                                amt = tx.get("amount", 0.0)
                                earned[a] = round(earned.get(a, 0.0) + amt, 8)
                                won[a] = won.get(a, 0) + 1
                                minted = round(minted + amt, 8)
                    node._net_acc = {"count": n, "minted": minted,
                                     "earned": earned, "won": won}
                    # recent + active only look at the last handful of blocks
                    recent = []
                    for b in blocks[-15:][::-1]:
                        if b.index == 0:
                            continue
                        paid = [tx for tx in b.transactions
                                if isinstance(tx, dict) and tx.get("type") == "reward"]
                        recent.append({"h": b.index, "t": b.timestamp, "miners": len(paid),
                                       "paid": round(sum(tx.get("amount", 0.0) for tx in paid), 8)})
                    active = []
                    if len(blocks) > 1:
                        active = sorted({tx.get("to") for tx in blocks[-1].transactions
                                         if isinstance(tx, dict) and tx.get("type") == "reward"})
                    roll = sorted(({"a": a, "n": nn, "blocks": won.get(a, 0)}
                                   for a, nn in earned.items()),
                                  key=lambda r: -r["n"])[:25]
                    payload = {"blocks": n, "minted": round(minted, 8),
                               "max_supply": MAX_SUPPLY, "miners": len(earned),
                               "active": active, "recent": recent, "roll": roll,
                               "protocol": PROTOCOL_VERSION, "version": NODE_VERSION}
                    node._network_cache = (time.time(), n, payload)
                    self._json(payload)

            elif self.path.startswith("/block"):
                # One block in full, so anyone can browse the chain like any
                # other public ledger rather than take our word for it.
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                want_hash = (q.get("hash", [""])[0] or "").strip().lower()
                try:
                    h = int(q.get("h", ["-1"])[0])
                except ValueError:
                    h = -1
                with node.lock:
                    chain = node.chain.chain
                    if want_hash:
                        h = next((b.index for b in chain
                                  if b.compute_hash().lower() == want_hash), -1)
                    if h < 0 or h >= len(chain):
                        self._json({"error": "no such block"}, 404); return
                    b = chain[h]
                    targets = compute_targets(chain)
                    target = targets[h] if h < len(targets) else MAX_TARGET
                    rewards = [t for t in b.transactions
                               if isinstance(t, dict) and t.get("type") == "reward"]
                    shares = [t for t in b.transactions
                              if isinstance(t, dict) and t.get("type") == "shares"]
                    share_list = shares[0].get("list", []) if shares else []
                    per_miner = {}
                    for s in share_list:
                        if isinstance(s, dict):
                            a = s.get("address")
                            per_miner[a] = per_miner.get(a, 0) + 1
                    self._json({
                        "height": b.index,
                        "hash": b.compute_hash(),
                        "pow_hash": b.pow_hash(),
                        "previous_hash": b.previous_hash,
                        "timestamp": b.timestamp,
                        "nonce": b.nonce,
                        "tx_hash": b.tx_hash,
                        "transactions": len(b.transactions),
                        "reward": round(sum(t.get("amount", 0) for t in rewards), 8),
                        "work_shares": len(share_list),
                        "shares_by": [{"address": a, "count": c}
                                      for a, c in sorted(per_miner.items(),
                                                         key=lambda kv: -kv[1])],
                        "difficulty_bits": (256 - target.bit_length() + 1) if target else 0,
                        "target": hex(target),
                        "paid": [{"to": t.get("to"), "amount": t.get("amount")}
                                 for t in rewards],
                        "raw": b.transactions,
                        "height_of_tip": len(chain) - 1,
                    })

            elif self.path.startswith("/transfers"):
                # Transfers never enter a block: they are agreed by stake-weighted
                # vote. Without this the whole payment side of the ledger would be
                # invisible to anyone browsing. Now paginated so the explorer can
                # walk the ENTIRE ledger (?limit=&offset=), not just the newest.
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                sig_want = (q.get("sig", [""])[0] or "").strip()
                try:
                    limit = int(q.get("limit", ["40"])[0])
                except ValueError:
                    limit = 40
                try:
                    offset = int(q.get("offset", ["0"])[0])
                except ValueError:
                    offset = 0
                if limit <= 0:
                    limit = 40
                with node.lock:
                    balances = node.get_balances()
                    total = len(node.confirmed_log)
                    out = []
                    seen = 0
                    for entry in reversed(node.confirmed_log):
                        tx = entry.get("tx", {})
                        sig = tx.get("signature", "")
                        if sig_want and not sig.startswith(sig_want):
                            continue
                        if not sig_want and seen < offset:
                            seen += 1
                            continue
                        votes = entry.get("votes", {})
                        yes = sum(max(balances.get(a, 0), 0.0)
                                  for a, v in votes.items() if v.get("approve"))
                        no = sum(max(balances.get(a, 0), 0.0)
                                 for a, v in votes.items() if not v.get("approve"))
                        out.append({
                            "signature": sig,
                            "from": tx.get("from"), "to": tx.get("to"),
                            "amount": tx.get("amount"), "timestamp": tx.get("timestamp"),
                            "voters": len(votes),
                            "weight_yes": round(yes, 8), "weight_no": round(no, 8),
                            "votes": [{"validator": a, "approve": bool(v.get("approve")),
                                       "weight": round(max(balances.get(a, 0), 0.0), 8)}
                                      for a, v in sorted(votes.items())],
                        })
                        if len(out) >= (1 if sig_want else limit):
                            break
                    pending = [{"from": t.get("from"), "to": t.get("to"),
                                "amount": t.get("amount"), "signature": s}
                               for s, t in node.transfers.items()
                               if s not in node.confirmed][:20]
                self._json({"confirmed": out, "pending": pending,
                            "total": total, "offset": offset, "limit": limit})

            elif self.path.startswith("/shares"):
                # Shares only ever travelled by push before, which quietly broke
                # the whole point of the coin: a miner behind a home router
                # cannot be pushed to, so it never received anyone else's work
                # and every block it won paid only itself. Letting nodes ASK for
                # shares is what makes the split work for people who cannot host.
                #
                # We serve the current tip's shares in the original flat form
                # (older nodes read only this), PLUS a "recent" list of shares
                # for the last few tips, each tagged with the tip it was mined
                # against. A block may legitimately include those recent-tip
                # shares (the validator accepts the same SHARE_WINDOW), so this
                # is what lets a slightly-late miner's work actually get paid.
                with node.lock:
                    node._ensure_share_height()
                    prev = node.cur_shares["prev"]
                    out = []
                    for addr, nonces in node.cur_shares["by"].items():
                        for nc in list(nonces)[:MAX_SHARES_PER_BLOCK]:
                            out.append({"address": addr, "nonce": nc})
                    recent = []
                    for tip_hash, by in list(node.recent_shares.items()):
                        if tip_hash == prev:
                            continue
                        for addr, nonces in by.items():
                            for nc in list(nonces)[:MAX_SHARES_PER_BLOCK]:
                                recent.append({"prev_hash": tip_hash,
                                               "address": addr, "nonce": nc})
                        if len(recent) >= MAX_SHARES_PER_BLOCK * SHARE_WINDOW:
                            break
                self._json({"prev_hash": prev,
                            "shares": out[:MAX_SHARES_PER_BLOCK],
                            "recent": recent[:MAX_SHARES_PER_BLOCK * SHARE_WINDOW]})

            elif self.path.startswith("/holders"):
                with node.lock:
                    balances = node.get_balances()
                    total = sum(max(b, 0.0) for b in balances.values())
                    rows = sorted(((a, b) for a, b in balances.items() if b > 0),
                                  key=lambda kv: -kv[1])[:200]
                self._json({"total": round(total, 8), "count": len(balances),
                            "holders": [{"address": a, "balance": round(b, 8),
                                         "share": round(100 * b / total, 4) if total else 0}
                                        for a, b in rows]})

            elif self.path.startswith("/address"):
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                a = (q.get("a", [""])[0] or "").strip()
                if not a.startswith("SOSA"):
                    self._json({"error": "not a SOSA address"}, 400); return
                with node.lock:
                    mined, blocks_paid, first, last = 0.0, 0, None, None
                    for b in node.chain.chain:
                        got = sum(t.get("amount", 0) for t in b.transactions
                                  if isinstance(t, dict) and t.get("type") == "reward"
                                  and t.get("to") == a)
                        if got:
                            mined += got
                            blocks_paid += 1
                            first = b.index if first is None else first
                            last = b.index
                    moves = []
                    for entry in node.confirmed_log:          # full log, not [-400:]
                        tx = entry.get("tx", {})
                        if tx.get("from") == a or tx.get("to") == a:
                            moves.append({"dir": "out" if tx.get("from") == a else "in",
                                          "amount": tx.get("amount"),
                                          "other": tx.get("to") if tx.get("from") == a
                                                   else tx.get("from"),
                                          "t": tx.get("timestamp"),
                                          "sig": tx.get("signature")})
                    moves.reverse()                           # newest first
                    total_moves = len(moves)
                    try:
                        limit = int(q.get("limit", ["0"])[0])
                        offset = int(q.get("offset", ["0"])[0])
                    except ValueError:
                        limit, offset = 0, 0
                    if offset > 0:
                        moves = moves[offset:]
                    if limit > 0:
                        moves = moves[:limit]
                    self._json({
                        "address": a,
                        "balance": round(node.get_balances().get(a, 0.0), 8),
                        "mined": round(mined, 8),
                        "blocks_paid": blocks_paid,
                        "first_block": first, "last_block": last,
                        "transfers": moves,
                        "transfers_total": total_moves,
                    })
            else:
                self._json({"error": "unknown"}, 404)

        def do_POST(self):
            if not self._gate():
                return
            cap = MAX_BODY_CHAIN if self.path == "/submit_chain" else MAX_BODY_DEFAULT
            try:
                body = self._read(cap)
            except ValueError:
                self.close_connection = True
                self._json({"error": "too large"}, 413); return
            except Exception:
                self._json({"error": "bad"}, 400); return

            if self.path == "/api/send":
                if not self._local():
                    self._json({"error": "localhost-only"}, 403); return
                try:
                    ok, msg = do_send(node, str(body.get("to", "")),
                                      float(body.get("amount", 0)))
                except (TypeError, ValueError):
                    ok, msg = False, "amount must be a number."
                self._json({"ok": ok, "message": msg})

            elif self.path == "/api/mine":
                if not self._local():
                    self._json({"error": "localhost-only"}, 403); return
                # Optionally set the payout address the UI passed in.
                pa = body.get("payout")
                if isinstance(pa, str) and pa.startswith("SOSA") and len(pa) == 44:
                    node.payout_address = pa
                msg = start_mining(node) if body.get("on") else stop_mining(node)
                self._json({"ok": True, "mining": node.mining,
                            "message": msg.split("\n")[0]})

            elif self.path == "/api/wallet/new":
                # Confirm/keep a new wallet. If the node already generated a fresh
                # one at startup (the common first-launch case), show THAT wallet's
                # phrase so what the user backs up is the wallet they'll actually
                # use. Otherwise mint a new one now. Either way, clear the "fresh"
                # flag so onboarding doesn't reappear.
                if not self._local():
                    self._json({"error": "localhost-only"}, 403); return
                try:
                    if getattr(node, "wallet_is_fresh", False) and getattr(node, "_fresh_phrase", None):
                        phrase = node._fresh_phrase
                        addr = node.wallet.address()
                    else:
                        w, phrase = Wallet.create_with_phrase()
                        with node.lock:
                            w.save_to_file(node.wallet_file, password=node.wallet_password)
                            node.wallet = w
                            node.payout_address = w.address()
                            node.registry[w.address()] = {"pubkey": w.public_key_hex()}
                        addr = w.address()
                    node.wallet_is_fresh = False
                    self._json({"ok": True, "address": addr, "phrase": phrase})
                except Exception as e:
                    self._json({"ok": False, "error": str(e)}, 400)

            elif self.path == "/api/wallet/import":
                if not self._local():
                    self._json({"error": "localhost-only"}, 403); return
                phrase = str(body.get("phrase", "")).strip()
                try:
                    w = Wallet.from_phrase(phrase)
                    with node.lock:
                        w.save_to_file(node.wallet_file, password=node.wallet_password)
                        node.wallet = w
                        node.payout_address = w.address()
                        node.registry[w.address()] = {"pubkey": w.public_key_hex()}
                        node.wallet_is_fresh = False
                    self._json({"ok": True, "address": w.address()})
                except Exception:
                    self._json({"ok": False,
                                "error": "those words didn't restore a wallet -- "
                                         "check the spelling and order"}, 400)

            elif self.path == "/block":
                try:
                    block = Block(body["index"], body["transactions"],
                                  body["previous_hash"], body["timestamp"], body["nonce"])
                except Exception:
                    self._json({"error": "bad block"}, 400); return
                self._json({"result": handle_incoming_block(node, block)})

            elif self.path == "/submit_chain":
                self._json({"result": handle_submit_chain(node, body)})

            elif self.path == "/register":
                addr, pub = body.get("address"), body.get("pubkey")
                url = body.get("url")
                fresh = False
                if addr and pub and addr == _address_from_pubkey(pub):
                    with node.lock:
                        if addr not in node.registry:
                            node.registry[addr] = {"pubkey": pub}
                            node.save_validators()
                            fresh = True

                if (isinstance(url, str) and url.startswith("http")
                        and url != node.my_url and url not in node.peers
                        and len(node.peers) < 25):
                    meet(node, url)
                    add_event(node, f"peer connected: {url}")
                if fresh:
                    gossip(node, "/register", body)
                self._json({"ok": True})

            elif self.path == "/tx":
                self._json({"result": handle_incoming_tx(node, body)})

            elif self.path == "/share":
                self._json({"result": handle_incoming_share(node, body)})

            elif self.path == "/schain_share":
                self._json({"result": handle_incoming_schain_share(node, body)})

            elif self.path == "/vote":
                self._json({"result": handle_incoming_vote(node, body)})

            else:
                self._json({"error": "unknown"}, 404)

        def note_inbound(self):
            """
            Someone from the open internet just connected to us, so we are
            reachable -- by definition, whatever our peers were able to prove.
            This matters because reachability used to be decided only by asking
            peers to call back, and when every peer sits behind a home router
            nobody can perform that test. The one genuinely public node on the
            network therefore believed it was unreachable and never announced
            itself to the relays, so the relay fallback -- the whole point of
            which is to work when the seed list does not -- had nothing to find.
            """
            try:
                who = self.client_address[0]
            except Exception:
                return
            if not who or who.startswith(("127.", "10.", "192.168.", "169.254.", "172.")):
                return
            if node.reachable:
                return
            host = self.headers.get("Host", "")
            host = host.split(",")[0].strip()
            if host and not host.startswith("localhost"):
                url = "http://" + host if "://" not in host else host
                if is_public_url(url):
                    with node.lock:
                        node.public_url = url.rstrip("/")
                        node.reachable = True

        def log_message(self, *a): pass
        def log_error(self, *a): pass

        def handle_one_request(self):
            try:
                super().handle_one_request()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                self.close_connection = True
    return H


def start_server(node):
    # allow_reuse_address (set on the class above) means the port is free the
    # instant the app closes, so reopening the wallet does not hit a still-held
    # socket -- which is what made it look like it only opened once.
    server = ThreadingHTTPServer(("0.0.0.0", node.port), make_handler(node))
    node.server = server
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"  Server listening on port {node.port}.")
    return server


def handle_incoming_share(node, s):
    if not isinstance(s, dict):
        return "ignored"
    prev_hash, addr, nonce = s.get("prev_hash"), s.get("address"), s.get("nonce")
    if not isinstance(addr, str) or not addr.startswith("SOSA") \
            or not isinstance(nonce, int) or not isinstance(prev_hash, str):
        return "ignored"

    # A seed does not mine, so it never needs shares for itself -- but it is the
    # only node most miners can reach, which makes it the only place they can
    # collect anyone else's work from. Relaying alone was not enough: passing a
    # share onward and keeping nothing meant /shares always answered "none", so
    # every miner behind a router built blocks containing only its own work and
    # paid only itself. That is why a miner's balance came out as an exact
    # multiple of the full block reward instead of a spread of fractions.
    #
    # So: keep them. Deliberately without verifying -- a seed earns nothing, so
    # it cannot be cheated out of anything, and checking each share costs a
    # memory-hard hash it should be spending on serving the network. Whoever
    # pulls a share verifies it before using it, and a block carrying a bad one
    # is rejected outright, so the arithmetic is still checked where it matters.
    if getattr(node, "seed_only", False):
        with node.lock:
            node._ensure_share_height()
            # A seed is the collection point most miners can reach, so it must be
            # at least as forgiving as a normal node about which tip a share was
            # mined against. Before, it kept only shares matching the *exact*
            # current tip and dropped everything a step behind -- so a miner that
            # lagged even one block (slow link to this seed) had its work
            # silently discarded and was paid almost nothing despite real
            # hashing. Now it keeps shares for the current tip AND the recent
            # tips the block validator already accepts (SHARE_WINDOW), so
            # slightly-late work still counts.
            if prev_hash == node.cur_shares["prev"]:
                bucket = node.cur_shares["by"].setdefault(addr, set())
                if len(bucket) < MAX_SHARES_PER_BLOCK and nonce not in bucket:
                    bucket.add(nonce)
                    node.cur_shares["version"] += 1
            elif prev_hash in node.recent_shares:
                bucket = node.recent_shares[prev_hash].setdefault(addr, set())
                if len(bucket) < MAX_SHARES_PER_BLOCK:
                    bucket.add(nonce)
        gossip(node, "/share", s)
        return "relayed"

    with node.lock:
        node._ensure_share_height()
        # accept a share if it targets the current tip OR one of the last few
        # tips -- this is what stops a fast miner from erasing everyone else's
        # work every time they find a block
        if prev_hash == node.cur_shares["prev"]:
            bucket = node.cur_shares["by"]
        elif prev_hash in node.recent_shares:
            bucket = node.recent_shares[prev_hash]
        else:
            return "stale"
        # validate the share's proof against the difficulty it was mined at
        st = share_target_for(next_target(node.chain.chain))
        if int(share_hash(prev_hash, addr, nonce), 16) >= st:
            return "invalid"
        nonces = bucket.setdefault(addr, set())
        if nonce in nonces:
            fresh = False
        else:
            nonces.add(nonce)
            if prev_hash == node.cur_shares["prev"]:
                node.cur_shares["version"] += 1
            fresh = True
    if fresh:
        gossip(node, "/share", s)
        return "accepted"
    return "duplicate"


# SHARE-CHAIN integration -- stage 1: receive a linked share-chain share, prove
# it, add it to the live share-chain, and pass it on. This runs alongside the
# old share path and changes nothing about validation, mining or payouts yet --
# it only builds the share-chain in the background so later stages (miners
# producing these, then the forcing rule) have a real, agreed record to stand on.
SHARECHAIN_KEEP = PPLNS_WINDOW + 100   # retain the payout window plus a margin


SCHAIN_PENDING_MAX = 500   # shares parked awaiting a parent, across all parents


def _schain_target_at(node, block_prev):
    """
    The share-chain target as of the block a share is anchored to. Deriving it
    from the anchor block -- not the validator's current tip -- means every node
    computes the SAME target for a given share no matter when it arrives. That
    is what stops a share being accepted by its maker yet rejected by a seed a
    few blocks later, which was silently dropping nearly every share in transit.
    Only recent anchors are searched (shares anchor to the current tip), so this
    stays cheap on a long chain.
    """
    chain = node.chain.chain
    lo = max(0, len(chain) - 40)
    for i in range(len(chain) - 1, lo - 1, -1):
        if chain[i].compute_hash() == block_prev:
            return sharechain_target(next_target(chain[:i + 1]))
    return None


def handle_incoming_schain_share(node, s):
    """
    Intake for one linked share-chain share. Proof and structure are checked,
    then it is placed in the chain. A share that arrives BEFORE its parent
    (gossip over a real network is out-of-order all the time) is PARKED and
    retried the moment the parent lands, instead of being thrown away --
    dropping those was exactly how a smaller miner's work silently vanished
    and their node fell permanently behind.
    """
    if not isinstance(s, dict):
        return "ignored"
    # CHEAP duplicate check FIRST. Verifying a share means two 8MB memory-hard
    # hashes (the id proof and the target check). The same share arrives many
    # times over a gossip network, and paying that price for every duplicate
    # pegged the seed at 100%. A share we already hold -- or already have parked
    # -- costs nothing to recognise, so recognise it before doing any work.
    sid = s.get("id")
    if isinstance(sid, str):
        with node.lock:
            if node.share_chain.has(sid):
                return "duplicate"
            pend = node.__dict__.setdefault("schain_pending", {})
            for bucket in pend.values():
                if any(x.get("id") == sid for x in bucket):
                    return "pending"
    if not share_id_is_valid(s):
        return "ignored"
    # the proof must clear the difficulty AS OF THE SHARE'S ANCHOR BLOCK, so
    # every node agrees on it regardless of how far its own tip has moved
    try:
        target = _schain_target_at(node, s.get("block_prev"))
        if target is None:
            # anchor not in our recent chain -- fall back to current difficulty
            target = sharechain_target(next_target(node.chain.chain))
    except Exception:
        return "ignored"
    if not share_meets_target(s, target):
        return "invalid"
    newly = []
    with node.lock:
        pend = node.__dict__.setdefault("schain_pending", {})
        res = _schain_place(node, s, pend, newly)
    if newly:
        node.save_share_chain()      # persist so a restart keeps these shares
    for sh in newly:
        gossip(node, "/schain_share", sh)
    return res


def _schain_place(node, s, pend, newly):
    """Place one proven share: park it if the parent is missing; on success,
    revive every parked descendant that was waiting on it, in order."""
    sp = s["share_prev"]
    if sp != SHARECHAIN_GENESIS and not node.share_chain.has(sp):
        total = sum(len(v) for v in pend.values())
        bucket = pend.setdefault(sp, [])
        if total < SCHAIN_PENDING_MAX and all(x["id"] != s["id"] for x in bucket):
            bucket.append(s)
        return "pending"
    st = _schain_add_one(node, s)
    if st != "accepted":
        return st
    newly.append(s)
    stack = [s["id"]]
    while stack:
        pid = stack.pop()
        for child in pend.pop(pid, []):
            if _schain_add_one(node, child) == "accepted":
                newly.append(child)
                stack.append(child["id"])
    node.share_chain.prune(SHARECHAIN_KEEP)
    return "accepted"


def _schain_add_one(node, s):
    """Uncle validation + add for a single share (no parking, no retry)."""
    known = set(node.share_chain.shares)
    sp = s["share_prev"]
    uncles = s.get("uncles", [])
    if uncles:
        # each uncle must be a share we hold and NOT an ancestor on this
        # share's own line (a real orphan, not a replay of the main chain)
        if sp != SHARECHAIN_GENESIS:
            ancestors = {x["id"] for x in node.share_chain.chain_from_tip(sp)}
        else:
            ancestors = set()
        for uid in uncles:
            if uid not in known or uid in ancestors or uid == s["id"]:
                return "invalid"
    if not node.share_chain.add(s):
        return "duplicate"
    return "accepted"


def mine_one_schain_share(node, address, max_tries=200000):
    """
    Produce ONE linked share-chain share: find a nonce whose share hashes under
    the share-chain target, building on the current tip and anchored to the
    current block. Adds it locally and relays it. Returns the share, or None if
    no nonce cleared the target within max_tries (the caller just tries again
    next pass). This is what actually fills the share-chain as a miner works.
    """
    with node.lock:
        tip = node.share_chain.tip or SHARECHAIN_GENESIS
        block_prev = node.chain.last_block.compute_hash()
        uncles = node.share_chain.uncle_candidates()
    try:
        target = sharechain_target(next_target(node.chain.chain))
    except Exception:
        return None
    nonce = random.randrange(1 << 62)
    for _ in range(max_tries):
        sid = sharechain_share_id(tip, block_prev, address, nonce, uncles)
        if int(sid, 16) < target:
            share = {"share_prev": tip, "block_prev": block_prev,
                     "address": address, "nonce": nonce,
                     "uncles": uncles, "id": sid}
            handle_incoming_schain_share(node, share)
            return share
        nonce += 1
    return None


def pull_schain(node):
    """
    Catch up the share-chain from peers. Ask each peer for its recent shares
    and feed them through the normal intake (which proves + links each one), so
    a node that fell behind rejoins the same share-chain everyone else is on.
    """
    added = 0
    for peer in list(node.peers)[:6]:
        data = get_json(peer.rstrip("/") + "/schain_shares", timeout=4)
        if not isinstance(data, dict):
            continue
        shares = data.get("shares")
        if not isinstance(shares, list):
            continue
        # oldest-first so each share's parent is present before its child
        for s in shares:
            res = handle_incoming_schain_share(node, s)
            if res == "accepted":
                added += 1
    return added


def handle_incoming_block(node, block):
    accepted = False
    need_sync = False
    with node.lock:
        last = node.chain.last_block
        if block.index <= last.index:
            pass
        elif block.index == last.index + 1 and validate_new_block(node.chain, block, share_chain=node.share_chain):
            node.chain.chain.append(block)
            node.save_chain()
            node._ensure_share_height()
            accepted = True
        else:
            need_sync = True
    if accepted:
        mine_addr = node.payout_address
        my_cut = round(sum(tx.get("amount", 0) for tx in block.transactions
                           if isinstance(tx, dict) and tx.get("type") == "reward"
                           and tx.get("to") == mine_addr), 8)
        paid = sum(1 for tx in block.transactions
                   if isinstance(tx, dict) and tx.get("type") == "reward")
        extra = f" -- my work-share paid +{my_cut:.8f} SOSA" if my_cut > 0 else ""
        add_event(node, f"block {block.index} from a peer ({paid} paid)"
                        + (f", my share +{my_cut:.6f}" if my_cut > 0 else ""))
        print(f"\n  [block] accepted block {block.index} from a peer "
              f"({paid} miner(s) paid){extra}\nsosa:{node.port}> ", end="", flush=True)
        threading.Thread(target=broadcast_block, args=(node, block), daemon=True).start()
        threading.Thread(target=push_chain_once, args=(node,), daemon=True).start()
        with node.lock:
            newly = node.retally()
        for sig in newly:
            announce_confirm(node, sig)
        return "accepted"
    if need_sync:
        threading.Thread(target=sync_once, args=(node,), daemon=True).start()
        return "resync"
    return "duplicate"


def broadcast_block(node, block):
    payload = block_to_dict(block)
    # Fan the block out to every peer AT ONCE. A block is a few KB; the only job
    # here is speed. Sent sequentially, a dead or slow address earlier in the set
    # made every live miner behind it wait out its timeout before the block even
    # left -- and because each re-broadcast hop repeated that stall, the delay
    # compounded and miners trailed the tip by a block or two. Same pattern
    # sync_chain already uses: hand the sends to the shared out-pool so dead peers
    # time out on their own threads, not in front of everyone. Fire-and-forget is
    # safe because push_chain re-offers any missing block every tick.
    for peer in list(node.peers):
        try:
            _out_pool.submit(post_json, peer.rstrip("/") + "/block", payload, 5)
        except Exception:
            pass


def push_chain(node):
    """
    Push our chain OUT to peers so a miner behind a home router still takes part:
    it can't accept incoming connections, so a reachable hub can never PULL its
    blocks -- instead the miner PUSHES. Each tick we ask a peer how tall its
    chain is (cheap) and only send our full chain when we're actually ahead. That
    keeps it light AND self-healing: if a push doesn't land, next tick we're still
    ahead and simply offer it again -- no cached flag that can get stuck.
    """
    with node.lock:
        n = len(node.chain.chain)
        if n <= 1 or not node.peers:
            return
        peers = list(node.peers)
    for peer in peers:
        base = peer.rstrip("/")
        info = get_json(base + "/info")
        peer_blocks = info.get("blocks", 0) if isinstance(info, dict) else 0
        if n <= peer_blocks:
            continue
        behind = n - peer_blocks

        # If they are only a little behind, send exactly the blocks they are
        # missing, in order. That is a few KB and lands immediately. Shipping
        # the entire chain for the sake of one new block meant a home upload
        # had to move most of a megabyte before a peer could learn about it --
        # slow, easy to time out, and when it timed out the block simply never
        # reached anyone. The miner kept winning blocks that nobody else ever
        # saw, then lost them all the moment it took someone else's chain.
        if behind <= 25:
            with node.lock:
                missing = [block_to_dict(b) for b in node.chain.chain[peer_blocks:]]
            sent_all = True
            for blk in missing:
                # A reply is not the same as delivery. /block answers with a JSON
                # result even when it did NOT apply the block -- "resync" (the peer
                # is on a different history and asked us to sync instead) or
                # "duplicate". Treating any non-None reply as success meant a home
                # peer sitting on a fork looked "caught up" here while it had
                # actually received nothing, so it never got the chain by push and
                # could stay stuck behind for good. Only "accepted" (or a peer that
                # is already at/above this block) counts as the block landing; on
                # anything else, fall through to the full submit_chain below, which
                # can carry a genuine reorg.
                resp = post_json(base + "/block", blk, timeout=15)
                res = resp.get("result") if isinstance(resp, dict) else None
                if res == "accepted":
                    continue
                if res == "duplicate":
                    # peer already had THIS block; keep offering the later ones
                    continue
                # None (network fail) or "resync" (fork) -> block-by-block won't take
                sent_all = False
                break
            if sent_all:
                continue

        # Far behind, or the block-by-block catch-up did not take: send the lot.
        with node.lock:
            payload = chain_to_list(node.chain)
        post_json(base + "/submit_chain", payload, timeout=90)


def handle_submit_chain(node, data):
    """A peer pushed its chain to us. Adopt it if it's valid and better, then
    relay it onward to our reachable peers (unreachable ones pull it themselves)."""
    try:
        cand = list_to_chain(data)
    except Exception:
        return "bad"
    with node.lock:
        # fast reject: skip full validation of chains that clearly can't win, so
        # the constant stream of same/shorter pushes stays cheap. Below the v6
        # flag day "can't win" == "not strictly longer" (the old length rule).
        # At/after it a shorter-but-heavier chain CAN win, so a same-or-shorter
        # push is only rejected outright while we're still below the flag; above
        # it we let is_better (work-aware) decide, since it may legitimately
        # prefer a shorter heavier chain. An identical chain is always dropped.
        cur_len = len(node.chain.chain)
        cand_len = len(cand.chain)
        cur_tip = node.chain.chain[-1].compute_hash() if node.chain.chain else None
        cand_tip = cand.chain[-1].compute_hash() if cand.chain else None
        if cand_tip == cur_tip:
            return "kept"                     # exactly what we already have
        both_past_v6 = (v6_active(cand_len - 1) and v6_active(cur_len - 1))
        # Cheap reject only for chains is_better could never prefer. Below v6 that
        # is a STRICTLY shorter chain (an equal-length one can still win the
        # deterministic lower-tip-hash tie-break, so it must reach is_better --
        # dropping it here is what made a pushed equal-length reorg silently fail
        # while a pull would have adopted it). Above v6 a shorter chain can be
        # heavier, so we never fast-reject on length there.
        if not both_past_v6 and cand_len < cur_len:
            return "kept"                     # pre-v6: strictly shorter can't win
    if not (cand.chain and cand.chain[0].compute_hash() == _CANONICAL_GENESIS_HASH):
        return "invalid"
    # Incremental validation. The overwhelming common case is a miner pushing
    # "our chain plus a block or two." Re-hashing all ~5,800 links on every such
    # push is what pegged the seed to 100% forever -- the cost grew with the
    # chain and miners push on every block. So when the candidate simply extends
    # the chain we already hold (its block at our tip height hashes to our tip),
    # only the NEW blocks are checked. A genuine reorg (different history) still
    # falls back to the full links check, which is rare.
    extends = (cur_len > 0 and len(cand.chain) > cur_len
               and cand.chain[cur_len - 1].compute_hash() == cur_tip)
    if extends:
        prev = cand.chain[cur_len - 1]
        for blk in cand.chain[cur_len:]:
            if blk.previous_hash != prev.compute_hash():
                return "invalid"
            # v6: pushed blocks obey the same median-time-past rule as mined ones
            if not timestamp_ok(cand.chain, blk):
                return "invalid"
            prev = blk
    else:
        # Structure and links only. Re-hashing every block and every work-share on
        # each push meant a couple of peers pushing normally could saturate the
        # machine for good -- and it was happening in sixteen threads at once. The
        # proof-of-work is confirmed gently in the background after adopting, and a
        # broken link is still caught right here, immediately.
        if not cand.is_chain_valid(links_only=True):
            return "invalid"
    adopted = False
    with node.lock:
        if is_better(cand, node.chain):
            node.chain = cand
            node.save_chain()
            node._ensure_share_height()
            node._last_push_len = len(cand.chain)
            adopted = True
    if adopted:
        # A seed must not do this. Miners push their chain here constantly, and
        # each push was starting a fresh deep verification of a hundred-odd
        # blocks and every work-share in them -- thousands of memory-hard
        # hashes. One finished, the next push arrived, it began again, and the
        # machine sat at 100% forever while answering nothing. The other two
        # launch points already skipped seeds; this one was missed.
        if not node.seed_only:
            threading.Thread(target=node._verify_chain_background,
                             args=(cand,), daemon=True).start()
        print(f"\n  [relay] adopted a pushed chain -> {len(cand.chain)} blocks"
              f"\nsosa:{node.port}> ", end="", flush=True)
        with node.lock:
            newly = node.retally()
        for sig in newly:
            announce_confirm(node, sig)
        # relay onward to reachable peers; home nodes get it via their own pull
        threading.Thread(target=push_chain_once, args=(node,), daemon=True).start()
    return "adopted" if adopted else "kept"


def handle_incoming_tx(node, tx):
    if not isinstance(tx, dict) or tx.get("type") != "transfer":
        return "ignored"
    if not transfer_is_valid(tx):
        return "invalid"
    sig = tx.get("signature")
    with node.lock:
        if sig in node.transfers:
            return "duplicate"
        if len(node.transfers) >= MAX_TRANSFERS:
            return "busy"                     # refuse to grow without bound
        node.transfers[sig] = tx
    gossip(node, "/tx", tx)
    if transfers_active(len(node.chain.chain)):
        # settled by the chain now -- just hold it for a miner to include, no vote
        print(f"\n  [tx] transfer received -- awaiting a block"
              f"\nsosa:{node.port}> ", end="", flush=True)
        return "accepted"
    print(f"\n  [tx] transfer received -- validators are voting..."
          f"\nsosa:{node.port}> ", end="", flush=True)
    cast_vote(node, tx)
    return "accepted"


def handle_incoming_vote(node, vote):
    if not vote_is_valid(vote):
        return "invalid"
    sig = vote["tx_signature"]
    fresh = False
    confirmed_now = False
    with node.lock:
        if vote["validator"] not in node.registry:
            if len(node.registry) >= MAX_REGISTRY:
                return "busy"                 # don't let the registry grow forever
            node.registry[vote["validator"]] = {"pubkey": vote["validator_pubkey"]}
            node.save_validators()
        # hearing from them is what makes their stake count
        node.seen_at[vote["validator"]] = time.time()
        # only start tracking votes for a brand-new transfer if we have room
        if (sig not in node.votes and sig not in node.transfers
                and len(node.votes) >= MAX_VOTE_TABLES):
            return "busy"
        table = node.votes.setdefault(sig, {})
        prev = table.get(vote["validator"])

        if prev is None or (vote["approve"] and not prev.get("approve")):
            table[vote["validator"]] = vote
            fresh = True
            if sig in node.transfers:
                confirmed_now = node.maybe_confirm(sig)
    if fresh:
        gossip(node, "/vote", vote)
    if confirmed_now:
        announce_confirm(node, sig)

    if fresh and sig not in node.transfers:
        threading.Thread(target=sync_once, args=(node,), daemon=True).start()
    return "ok"


MAX_FORK_DEPTH = 25      # how far "behind" a peer can be and still be checked as a
                         # possible better (heavier) chain -- lets a node climb off a fork

def sync_chain(node):
    if not node.peers:
        return
    mine = len(node.chain.chain)

    # Ask who is actually ahead before downloading anything. Pulling the whole
    # chain from every peer on every cycle -- even when already up to date --
    # was most of the work this loop did.
    #
    # Ask them ALL, and ask them at once. Checking only the first handful meant
    # that when the peer list was mostly dead addresses, the one reachable node
    # could simply not get asked: the node then believed nobody was ahead, went
    # quiet, mined its own private fork, and lost every block of it the moment
    # it reconnected to the real chain. Peer sets have no order, so "the first
    # few" is a coin toss. /info is a few bytes; there is no reason to ration it.
    peers = list(node.peers)
    ahead = []
    if peers:
        # Take answers as they arrive. Waiting on the batch as a whole meant a
        # few dead addresses could time the operation out and discard replies
        # that had already come back -- including the only peer that actually
        # had the chain.
        futures = {}
        for p in peers:
            try:
                futures[_out_pool.submit(get_json, p.rstrip("/") + "/info", 30)] = p
            except Exception:
                pass
        # Whoever answers first, counts first. Waiting on each peer in turn meant
        # one slow or dead address at the front of the queue held up every reply
        # behind it -- so a generous timeout, needed for peers on the other side
        # of the world, ended up slowing everyone down instead. Now a nearby peer
        # answers in milliseconds and we move on; a distant one still gets its
        # full eight seconds, but only in the background.
        try:
            from concurrent.futures import as_completed
            for fut in as_completed(list(futures), timeout=35):
                p = futures[fut]
                try:
                    info = fut.result(timeout=0)
                except Exception:
                    continue
                # Consider peers even if I'm a few blocks "ahead" of them: I might
                # be ahead ON A FORK, and the real chain can be shorter. is_better
                # (heaviest-chain, post-flag) then correctly drops my fork for the
                # heavier honest chain. MAX_FORK_DEPTH bounds the extra downloads.
                if info and isinstance(info.get("blocks"), int) \
                        and info["blocks"] >= mine - MAX_FORK_DEPTH:
                    ahead.append((info["blocks"], p))
                # enough to work with, and someone is ahead: stop waiting
                if len(ahead) >= 3:
                    break
        except Exception:
            pass

    good = {p for _, p in ahead}
    for p in peers:
        if p in good:
            node.peer_misses.pop(p, None)
            node.peer_seen[p] = time.time()      # remember it was alive just now
        else:
            node.peer_misses[p] = node.peer_misses.get(p, 0) + 1
            if node.peer_misses[p] >= 5 and p not in HARDCODED_SEEDS:
                node.peers.discard(p)
                node.peer_misses.pop(p, None)
    if not ahead:
        return
    ahead.sort(reverse=True)

    # Being strictly behind a live peer proves we are in touch with a moving,
    # real tip -- remember it. This, not our own mined height, is what tells an
    # actively-mining node it is on the network and not on a private island.
    if ahead and ahead[0][0] > mine:
        node._last_peer_adopt = time.time()

    best, source = node.chain, None
    for _, peer in ahead[:3]:
        cand = None
        # FAST PATH: fetch ONLY the blocks we are missing and extend our own
        # chain, instead of re-downloading the whole multi-MB chain to catch up
        # one or two blocks. That full re-download is what kept pull-only miners
        # (behind a home router, can't be pushed to) perpetually a block behind.
        # ?from=N returns just blocks N onward -- a few KB. If the peer is old
        # (ignores ?from and returns the whole chain) or we have diverged (a
        # reorg, so the piece won't join our tip), we fall through to the full
        # download below. Links-only validation keeps a slow CPU at the tip.
        try:
            cur = len(node.chain.chain)
            part = get_json(peer.rstrip("/") + "/chain?from=" + str(cur), timeout=30)
        except Exception:
            part = None
        if isinstance(part, list) and part and isinstance(part[0], dict) \
                and part[0].get("index") == cur \
                and part[0].get("previous_hash") == node.chain.last_block.compute_hash():
            try:
                merged = chain_to_list(node.chain) + part
                c = list_to_chain(merged)
                if (c.chain and c.chain[0].compute_hash() == _CANONICAL_GENESIS_HASH
                        and c.is_chain_valid(links_only=True)):
                    cand = c
            except Exception:
                cand = None
        # FALLBACK: the whole chain (original behaviour) -- far behind, a reorg,
        # or a peer without ?from support. A once-per-catch-up cost; give it room.
        if cand is None:
            data = get_json(peer.rstrip("/") + "/chain", timeout=120)
            if data is None:
                continue
            c = list_to_chain(data)
            if not (c.chain and c.chain[0].compute_hash() == _CANONICAL_GENESIS_HASH
                    and c.is_chain_valid(links_only=True)):
                continue
            cand = c
        if is_better(cand, best):
            best, source = cand, peer
    if source is None:
        return
    switched = False
    with node.lock:
        if is_better(best, node.chain):
            node.chain = best
            node.save_chain()
            node._ensure_share_height()
            node._last_peer_adopt = time.time()
            switched = True
    if switched:
        print(f"\n  [sync] adopted a better chain from {source} "
              f"-> {len(best.chain)} blocks\nsosa:{node.port}> ", end="", flush=True)
        # Confirm the proof-of-work off the main thread, gently. This uses the
        # same throttled verifier as start-up: running it flat out pinned the
        # only processor and made the node stop answering entirely.
        if not node.seed_only:
            threading.Thread(target=node._verify_chain_background,
                             args=(best,), daemon=True).start()
        with node.lock:
            newly = node.retally()
        for sig in newly:
            announce_confirm(node, sig)


def sync_transfers(node):
    for peer in list(node.peers):
        state = get_json(peer.rstrip("/") + "/state")
        if not state:
            continue
        with node.lock:
            for addr in state.get("live", []):
                if isinstance(addr, str):
                    node.seen_at[addr] = time.time()
            for addr, info in state.get("registry", {}).items():
                pub = info.get("pubkey")
                if addr not in node.registry and pub \
                        and addr == _address_from_pubkey(pub):
                    node.registry[addr] = {"pubkey": pub}
            node.save_validators()
            adopted = []
            for entry in state.get("log", []):
                tx, votes = entry.get("tx", {}), entry.get("votes", {})
                sig = tx.get("signature")
                if not sig or sig in node.confirmed:
                    continue
                if not transfer_is_valid(tx):
                    continue
                good_votes = {a: v for a, v in votes.items()
                              if vote_is_valid(v) and v.get("tx_signature") == sig
                              and v.get("validator") == a}
                balances = node.get_balances()
                total = node.all_stake(balances)
                yes = sum(max(balances.get(a, 0), 0.0)
                          for a, v in good_votes.items()
                          if v.get("approve") and a in node.registry)
                if total > 0 and yes * 2 > total:
                    # A majority can only ever confirm a transfer that is
                    # arithmetically possible. Votes decide *ordering and
                    # agreement*; they can never conjure coins that were never
                    # mined, so an overdraft is refused no matter who signed it.
                    bal = balances.get(tx["from"], 0)
                    spent = node._committed_outgoing(tx["from"], sig)
                    if bal - spent + 1e-9 < tx["amount"]:
                        continue
                    node.transfers[sig] = tx
                    node.votes.setdefault(sig, {}).update(good_votes)
                    node.confirmed_log.append({"tx": tx, "votes": good_votes})
                    node.confirmed.add(sig)
                    adopted.append(sig)
            if adopted:
                node.save_transfers()
        for sig in adopted:
            announce_confirm(node, sig)


def pull_shares(node):
    if getattr(node, "seed_only", False):
        return 0        # a seed keeps what is pushed to it; it never needs more
    """
    Ask peers for the work-shares they have collected.

    Without this a miner that cannot accept incoming connections never learns
    about anyone else's work, so the blocks it wins pay nobody but itself --
    which looks exactly like the split being broken, and effectively is.
    """
    with node.lock:
        node._ensure_share_height()
        tip = node.cur_shares["prev"]
    if not tip:
        return
    st = share_target_for(next_target(node.chain.chain))
    added = 0
    for peer in list(node.peers)[:6]:
        data = get_json(peer.rstrip("/") + "/shares", timeout=3)
        if not isinstance(data, dict):
            continue
        # current-tip shares: only meaningful if the peer is on our tip
        if data.get("prev_hash") == tip:
            for item in (data.get("shares") or [])[:MAX_SHARES_PER_BLOCK]:
                if not isinstance(item, dict):
                    continue
                addr, nonce = item.get("address"), item.get("nonce")
                if not isinstance(addr, str) or not addr.startswith("SOSA") \
                        or not isinstance(nonce, int):
                    continue
                with node.lock:
                    if node.cur_shares["prev"] != tip:
                        return added
                    bucket = node.cur_shares["by"].setdefault(addr, set())
                    if nonce in bucket:
                        continue
                # only pay for the hash once we know it is new to us
                if int(share_hash(tip, addr, nonce), 16) >= st:
                    continue
                with node.lock:
                    if node.cur_shares["prev"] == tip:
                        node.cur_shares["by"].setdefault(addr, set()).add(nonce)
                        node.cur_shares["version"] += 1
                        added += 1
        # recent-tip shares: each carries the tip it was mined against. Accept any
        # that target a tip we are still tracking -- this is what rescues a
        # slightly-late miner's work, which the block builder already pays out
        # for recent tips within the window.
        for item in (data.get("recent") or [])[:MAX_SHARES_PER_BLOCK * SHARE_WINDOW]:
            if not isinstance(item, dict):
                continue
            rp, addr, nonce = item.get("prev_hash"), item.get("address"), item.get("nonce")
            if not isinstance(addr, str) or not addr.startswith("SOSA") \
                    or not isinstance(nonce, int) or not isinstance(rp, str):
                continue
            with node.lock:
                on_current = (rp == node.cur_shares["prev"])
                if not on_current and rp not in node.recent_shares:
                    continue                       # a tip we are not tracking
                have = (node.cur_shares["by"] if on_current
                        else node.recent_shares[rp]).get(addr, set())
                if nonce in have:
                    continue
            if int(share_hash(rp, addr, nonce), 16) >= st:
                continue
            with node.lock:
                if rp == node.cur_shares["prev"]:
                    node.cur_shares["by"].setdefault(addr, set()).add(nonce)
                    node.cur_shares["version"] += 1
                    added += 1
                elif rp in node.recent_shares:
                    node.recent_shares[rp].setdefault(addr, set()).add(nonce)
                    added += 1
        if added >= MAX_SHARES_PER_BLOCK * 2:
            break
    return added


def sync(node):
    sync_chain(node)
    try:
        pull_shares(node)
    except Exception:
        pass
    try:
        pull_schain(node)     # keep our share-chain caught up with the network
    except Exception:
        pass
    sync_transfers(node)
    reconcile_chain_transfers(node)   # settle in-block transfers: confirm + drop from pending
    revote_pending(node)
    push_chain(node)          # shove our blocks OUT so unreachable miners still count
    # Honest sync flag: we are 'synced' only when our chain is actually at or near
    # the height our peers report -- NOT merely because peers exist. (Setting it on
    # peer-existence alone made the app say "synced" while stuck on the genesis
    # block, so an imported wallet's balance never showed.) When we have no peers
    # we can't compare, so we don't claim synced.
    try:
        peers = list(node.peers)
        if peers:
            mine = len(node.chain.chain)
            best_seen = 0
            for p in peers[:6]:
                info = get_json(p.rstrip("/") + "/info", timeout=4)
                if info and isinstance(info.get("blocks"), int):
                    best_seen = max(best_seen, info["blocks"])
            # near = within a couple blocks of the best height anyone reports
            if best_seen and mine >= best_seen - 2:
                node.has_synced = True
            elif best_seen and mine < best_seen - 2:
                node.has_synced = False   # we're behind: NOT synced, keep pulling
    except Exception:
        pass


def rebroadcast_transfers(node):
    """
    Re-send our still-unconfirmed transfers every so often.

    A transfer is gossiped ONCE when you hit send. If that single push fails --
    a peer momentarily unreachable, a 2-second timeout against a busy/throttled
    seed, or the send firing before peers were fully connected -- the transfer
    used to be stranded in the sender's pending pool forever: the app said
    "sent", but no other node ever received it, so no miner could carry it into
    a block. This loop fixes that: as long as a transfer of ours hasn't been
    confirmed on-chain yet, we keep re-broadcasting it until it lands.
    """
    while True:
        time.sleep(20)
        try:
            with node.lock:
                me = node.wallet.address() if node.wallet else None
                # our own transfers that haven't been confirmed yet
                mine = [tx for sig, tx in node.transfers.items()
                        if sig not in node.confirmed
                        and tx.get("from") == me]
            if not mine or not node.peers:
                continue
            for tx in mine[:20]:      # cap so we never flood
                gossip(node, "/tx", tx)
        except Exception:
            pass


def auto_sync_loop(node):
    # A seed receives blocks pushed to it by miners, so it does not need to go
    # looking for the tip constantly. Checking far less often keeps it idle.
    interval = 30 if getattr(node, "seed_only", False) else SYNC_INTERVAL
    tick = 0
    # sync once immediately so a fresh miner builds on the network's tip
    # instead of starting its own island from genesis
    try:
        sync(node)
    except Exception:
        pass
    # A fresh node (still on the genesis block) MUST download the real chain
    # before it's useful -- otherwise it sits at height 1 forever and an imported
    # wallet's balance never appears. The single immediate sync above can run
    # before load_seeds has finished adding peers, so it finds nobody and does
    # nothing. Here we retry sync briefly and insistently until we've actually
    # left genesis, so the chain pull can't be missed just because of startup
    # timing. Once we're past a handful of blocks, the normal loop takes over.
    if not getattr(node, "seed_only", False):
        for _ in range(20):                     # ~20 tries, 3s apart = up to 1 min
            with node.lock:
                h = len(node.chain.chain)
                has_peers = len(node.peers) > 0
            if h > 2:
                break                            # we've adopted a real chain
            if has_peers:
                try:
                    sync_chain(node)             # force the pull now
                except Exception:
                    pass
            time.sleep(3)
    while True:
        time.sleep(interval)
        tick += 1
        try:
            sync(node)
            if tick % 3 == 0:
                exchange_peers(node)
        except Exception:
            pass


def introduce_self(node, peer):
    post_json(peer.rstrip("/") + "/register",
              {"address": node.wallet.address(),
               "pubkey": node.wallet.public_key_hex(),
               "url": node.my_url})


def exchange_peers(node):
    if len(node.peers) >= 25:
        return
    for peer in list(node.peers):
        data = get_json(peer.rstrip("/") + "/peers")
        if not data:
            continue
        for url in data.get("peers", []):
            if len(node.peers) >= 25:
                return
            # Only add addresses we can actually reach. Gossip is full of other
            # people's LAN addresses (10.x, 192.168.x, 169.254.x) which can never
            # serve us the chain -- adding them just fills the peer list with dead
            # ends and starves out the real reachable nodes, leaving us unable to
            # sync at all. is_public_url filters those out.
            if url and url != node.my_url and url not in node.peers \
                    and is_public_url(url):
                if meet(node, url):
                    add_event(node, f"discovered peer {url}")
                    print(f"\n  [peers] learned about {url} from the network"
                          f"\nsosa:{node.port}> ", end="", flush=True)


# Where to find the network. Order of preference:
#   1. a local seeds.txt next to this file (lets anyone point at their own nodes)
#   2. the community seed list published on the web
#   3. HARDCODED_SEEDS below -- baked into the client so a fresh download always
#      connects even if no website is up. Add more reachable nodes here over time.
DEFAULT_SEEDS_URL = "https://sosaiem.com/seeds.txt"
HARDCODED_SEEDS = [
    "http://134.209.125.53:80",
]


def _clean_urls(lines):
    out = []
    for ln in lines:
        ln = ln.strip()
        if ln and not ln.startswith("#") and ln.startswith("http"):
            out.append(ln.rstrip("/"))
    return out


_PRIVATE_PREFIXES = ("127.", "10.", "192.168.", "169.254.", "0.", "255.",
                     "192.0.2.", "198.51.100.", "203.0.113.")
LEARNED_SEEDS_FILE = "seeds_learned.txt"


def is_public_url(url):
    """
    Could somebody on the other side of the world reach this address?

    A node's address on its own wifi (192.168.x.x) is perfectly good for
    talking to the machine next to it and completely useless as a way into the
    network. Publishing one as a seed just hands newcomers a dead end.

    The subtle one is 100.64-127.x: that means the internet provider has put
    the customer behind their own layer of NAT, so the address looks public but
    nothing can ever connect to it. Those must be filtered too, or half the
    published seeds would be addresses that can never answer.
    """
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return False
    if not host or host in ("localhost", "::1"):
        return False
    if host.startswith(_PRIVATE_PREFIXES):
        return False
    parts = host.split(".")
    if len(parts) == 4:
        try:
            a, b = int(parts[0]), int(parts[1])
        except ValueError:
            return True                       # a hostname, not an IP -- allow it
        if a == 172 and 16 <= b <= 31:        # private range
            return False
        if a == 100 and 64 <= b <= 127:       # carrier-grade NAT, never reachable
            return False
    return True


# A peer that answered within this many seconds still counts as a way in, even
# if it doesn't answer the very instant we re-check. Home nodes flicker (a VPN
# hiccup, a brief drop); dropping them from the entry-point list the moment they
# blink made a healthy multi-node network look like it had collapsed back to one
# machine. The grace window shows the network as it actually is over the last few
# minutes, not just this exact second.
PEER_GRACE_SECONDS = 300


def good_seeds(node, verify=False, limit=20):
    """
    The entry points this node would recommend to a newcomer: public addresses,
    running our coin, that were reachable recently -- not only ones answering
    this exact instant, so a node mid-flicker still counts as a way in.
    """
    now = time.time()
    with node.lock:
        candidates = [p for p in node.peers if is_public_url(p)]
        if node.reachable and node.public_url and is_public_url(node.public_url):
            candidates.append(node.public_url)
        seen_map = dict(node.peer_seen)
    seen, out = set(), []
    for url in candidates:
        u = url.rstrip("/")
        if u in seen:
            continue
        seen.add(u)
        if verify:
            if (now - seen_map.get(u, 0)) <= PEER_GRACE_SECONDS:
                pass                              # answered recently -- keep it
            elif _answers(u, timeout=3):
                node.peer_seen[u] = now           # answers now -- refresh + keep
            else:
                continue                          # not recent and silent -- drop
        out.append(u)
        if len(out) >= limit:
            break
    return sorted(out)


def save_learned_seeds(node):
    """
    Keep our own list of ways back in, so this node can rejoin later without
    anyone editing a file. The operator's seeds.txt is never touched -- that
    one belongs to them, this one belongs to the node.
    """
    seeds = good_seeds(node, verify=True)
    if not seeds:
        return 0
    try:
        with open(LEARNED_SEEDS_FILE, "w") as f:
            f.write("# Written by the node itself -- addresses that were\n"
                    "# answering and reachable from the wider internet.\n"
                    "# Safe to delete; it will be rebuilt.\n")
            for s in seeds:
                f.write(s + "\n")
        return len(seeds)
    except Exception:
        return 0


def seed_keeper(node):
    """Refresh the remembered ways in, quietly, for as long as we run."""
    while True:
        time.sleep(300)
        try:
            save_learned_seeds(node)
        except Exception:
            pass


def nostr_announce(node):
    """
    Publish this node's address to relays nobody here controls.

    Only reachable nodes announce -- publishing an address that cannot accept
    connections just wastes a newcomer's time.
    """
    if node.no_nostr:
        return 0
    with node.lock:
        url = node.public_url if node.reachable else None
    if not url or not is_public_url(url):
        return 0
    try:
        sk = nostrseed.identity_from(node.wallet.public_key_bytes())
        return nostrseed.announce(sk, url, _CANONICAL_GENESIS_HASH)
    except Exception:
        return 0


def nostr_announce_loop(node):
    """Re-announce now and then, since relays drop old messages."""
    first = True
    while True:
        time.sleep(20 if first else 1800)
        first = False
        try:
            n = nostr_announce(node)
            if n:
                add_event(node, f"announced to {n} relay(s)")
        except Exception:
            pass


def nostr_discover(node, quiet=True):
    """Ask relays which nodes are out there, and connect to any that answer."""
    if node.no_nostr:
        return 0
    try:
        urls = nostrseed.discover(_CANONICAL_GENESIS_HASH, timeout=6)
    except Exception:
        return 0
    joined = 0
    for url in urls:
        with node.lock:
            known = url in node.peers
        if known or url == node.my_url or not is_public_url(url):
            continue
        if _answers(url, timeout=4) and meet(node, url):
            joined += 1
    if joined and not quiet:
        print(f"\n  [relays] found {joined} node(s) published on Nostr -- "
              f"no seed file involved."
              f"\nsosa:{node.port}> ", end="", flush=True)
    if joined:
        add_event(node, f"found {joined} node(s) via relays")
        save_learned_seeds(node)
    return joined


def nostr_discover_loop(node):
    """Keep an eye on the relays, so the file never has to be right."""
    while True:
        time.sleep(60)
        try:
            nostr_discover(node, quiet=False)
        except Exception:
            pass
        time.sleep(840)


def _seed_sources(node):
    """
    Every way we know of to find the network, gathered rather than chained.

    The old version stopped at the first source that produced *any* address,
    so a single stale line in seeds.txt would hide the working fallbacks behind
    it and strand a newcomer. Losing one entry point should never be fatal, so
    now we collect them all and try the lot.

    Order is by how likely each is to still be right: peers we have actually
    spoken to, then a file the operator controls, then the published list, then
    the address baked into this build.
    """
    sources = []
    if "--isolated" in sys.argv:
        # --isolated: talk to nobody but peers we were explicitly handed. This is
        # what keeps a local test from reaching the real network and pulling the
        # live chain into the test. (Checked via sys.argv because load_seeds runs
        # before node.isolated is assigned.)
        with node.lock:
            remembered = sorted(node.peers)
        return [("test peers", remembered)] if remembered else []
    with node.lock:
        remembered = sorted(node.peers)
    if remembered:
        sources.append(("peers we met before", remembered))
    if os.path.exists(LEARNED_SEEDS_FILE):
        try:
            with open(LEARNED_SEEDS_FILE) as f:
                found = _clean_urls(f)
            if found:
                sources.append(("ways in we found ourselves", found))
        except Exception:
            pass
    if os.path.exists("seeds.txt"):
        try:
            with open("seeds.txt") as f:
                found = _clean_urls(f)
            if found:
                sources.append(("seeds.txt", found))
        except Exception:
            pass
    try:
        with urllib.request.urlopen(DEFAULT_SEEDS_URL, timeout=4) as r:
            found = _clean_urls(r.read().decode(errors="ignore").splitlines())
        if found:
            sources.append(("the published list", found))
    except Exception:
        pass
    if HARDCODED_SEEDS:
        sources.append(("the address built into this app", _clean_urls(HARDCODED_SEEDS)))
    return sources


def _answers(url, timeout=4):
    """Is anything actually there, and is it the same coin as us?"""
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/info", timeout=timeout) as r:
            info = loads_strict(r.read())
    except Exception:
        return False
    if not isinstance(info, dict):
        return False
    genesis = info.get("genesis")
    # older builds do not report a genesis; give them the benefit of the doubt
    return genesis is None or genesis == _CANONICAL_GENESIS_HASH


def load_seeds(node):
    tried, live, worked = set(), 0, []
    for label, urls in _seed_sources(node):
        hits = 0
        for url in urls:
            if url in tried or url == node.my_url or len(tried) >= 25:
                continue
            tried.add(url)
            if not _answers(url):
                continue
            hits += 1
            live += 1
            meet(node, url)
        if hits:
            worked.append(f"{hits} from {label}")
        if live >= 5:            # a handful of good ways in is plenty
            break

    if live:
        print(f"  Joined the network via {live} node(s): {', '.join(worked)}.")
        add_event(node, f"bootstrapped via {live} node(s)")
        # One live node is enough to learn about all the others. This is what
        # stops the network depending on whichever address happened to be
        # baked into the download.
        learned = 0
        for peer in list(node.peers)[:3]:
            data = get_json(peer.rstrip("/") + "/seeds")
            if not isinstance(data, dict):
                continue
            for url in data.get("seeds", [])[:20]:
                if (isinstance(url, str) and url not in tried
                        and is_public_url(url) and url != node.my_url):
                    tried.add(url)
                    if meet(node, url):
                        learned += 1
        if learned:
            print(f"  Learned {learned} more way(s) in from the network itself.")
        save_learned_seeds(node)
        # CRITICAL: now that we actually have peers, pull the network's chain
        # immediately. Without this, a fresh miner joins the network socially
        # (peers show up) but keeps sitting on its lone genesis block until the
        # background sync loop happens to run -- and if the user hits "mine" in
        # that gap, they start mining a dead fork from block 1. Syncing here,
        # inline, closes that window: by the time bootstrap reports success the
        # node is already on the network's tip. Also mark that we've synced, so
        # mining can refuse to start until this has happened at least once.
        try:
            sync(node)
        except Exception:
            pass
        node.has_synced = True
        return True

    if not tried:
        print("  No way in is configured. Asking the public relays\u2026")
    else:
        print(f"  Tried {len(tried)} known address(es) and none answered.")
        print("  Asking the public relays instead\u2026")
    if nostr_discover(node):
        with node.lock:
            n = len(node.peers)
        print(f"  Joined via the relays -- {n} node(s), no seed file needed.")
        save_learned_seeds(node)
        return True
    print("  Nothing answered there either. Either everything is offline")
    print("  or this computer has no internet. Mining still works -- you")
    print("  will just be building on your own. It retries by itself.")
    add_event(node, "found no way into the network yet")
    return False


def retry_bootstrap(node):
    """
    Keep looking for a way in, so a node that started while every entry point
    was down still joins later without anyone restarting it.

    Two ways to notice we are cut off:
      1. Plain isolation -- our chain height has not moved for a few minutes.
      2. Miner isolation -- height IS moving, but only because WE are mining it.
         A miner that has fallen onto a private/minority fork keeps extending
         its own chain for ever, so check (1) never fires (its height keeps
         climbing). The real tell is that the network has not shown us anyone
         ahead in a long time: a node truly on the network loses the occasional
         block race and adopts the winner's chain; an islanded miner never
         does, because it is the biggest fish in a tiny pond. When that happens,
         go back to the seed list to find a node OUTSIDE our island. This is
         what let a mining node sit 20+ blocks behind until someone restarted.
    """
    delay = 30
    last_height = -1
    stuck_for = 0
    last_reseed = 0.0
    baseline = time.time()            # if we never adopt, measure "marooned" from here
    while True:
        time.sleep(delay)
        now = time.time()
        with node.lock:
            alone = not node.peers
            height = len(node.chain.chain)
        mining = not getattr(node, "seed_only", False)

        # (1) plain isolation: height frozen
        if height == last_height:
            stuck_for += 1
        else:
            stuck_for = 0
            last_height = height

        # (2) miner isolation: no network-sourced progress in a while.
        # _last_peer_adopt is stamped by sync_chain whenever a peer is strictly
        # ahead of us or we adopt their chain. Our OWN mined blocks never touch
        # it -- which is the whole point.
        last_adopt = getattr(node, "_last_peer_adopt", baseline)
        # A node that is actually on the network loses the occasional block race
        # and adopts within a block or two. If we're MINING and haven't heard a
        # better tip from anyone in ~90s, we're very likely extending a private
        # fork -- so re-seed fast to find a node outside our island. (This used to
        # wait 5 minutes, which meant a miner could pile up a minute-plus of
        # wasted, soon-to-be-orphaned blocks before rejoining.)
        marooned = (mining
                    and (now - last_adopt) > 90       # ~90s with nobody ahead
                    and (now - last_reseed) > 45)     # re-seed at most every 45s

        if alone or stuck_for >= 6 or marooned:
            found = load_seeds(node)
            last_reseed = now
            if found and not alone:
                stuck_for = 0        # found fresh addresses; give them a chance
            elif alone and found:
                return
            delay = min(delay * 2, 600) if alone else 30
        else:
            delay = 30


def check_peer_rules(node, peer):
    """
    Ask a peer which rules it plays by and say something if they differ.

    We warn rather than refuse. Cutting off a peer over a version number would
    cause exactly the split we are trying to avoid -- and during an upgrade the
    two sides genuinely do need to keep talking. What matters is that the
    disagreement is visible to a human instead of silently forking the chain.
    """
    info = get_json(peer.rstrip("/") + "/info")
    if not isinstance(info, dict):
        return
    with node.lock:
        if peer in node.warned_peers:
            return
    theirs = info.get("protocol")
    genesis = info.get("genesis")

    trouble = None
    if genesis and genesis != _CANONICAL_GENESIS_HASH:
        trouble = ("a DIFFERENT GENESIS BLOCK -- this is a separate coin, not a "
                   "different version of ours. Nothing will ever sync between us.")
    elif theirs is None:
        trouble = ("a build too old to say which rules it follows. It may not "
                   "understand blocks we consider valid.")
    elif theirs != PROTOCOL_VERSION:
        trouble = (f"consensus rules v{theirs}, and we follow v{PROTOCOL_VERSION}. "
                   "One of us is out of date; until that is fixed the two sides "
                   "can drift onto different chains.")
    if not trouble:
        return
    with node.lock:
        node.warned_peers.add(peer)
    print(f"\n  [!] {peer} is running {trouble}"
          f"\n      Get the current build from https://sosaiem.com"
          f"\nsosa:{node.port}> ", end="", flush=True)
    add_event(node, f"peer {peer} runs different rules")


def confirm_reachable(node):
    """
    Ask peers whether they can actually reach us, and believe them over
    ourselves. A node that merely *thinks* it is reachable poisons everyone
    else's peer list with an address that never answers.
    """
    for peer in list(node.peers)[:6]:
        try:
            data = get_json(peer.rstrip("/") + f"/reachme?port={node.port}")
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        if data.get("reachable"):
            seen_as = data.get("seen_as")
            with node.lock:
                node.reachable = True
                if seen_as:
                    node.public_url = f"http://{seen_as}:{node.port}"
            return True
    with node.lock:
        node.reachable = False
    return False


def open_the_door(node):
    """
    Try to become a node other people can join through.

    This runs in the background at start-up: ask the router to forward our
    port, then get a peer to confirm it worked. Every node that succeeds is one
    less reason for the whole network to depend on a single server.
    """
    if node.no_upnp:
        return
    ok, detail = (False, "skipped")
    try:
        ok, detail = portmap.open_port(node.port)
    except Exception as e:
        ok, detail = False, f"{type(e).__name__}"
    if ok:
        node.upnp_opened = True
        print(f"\n  [door] {detail} opened port {node.port} for this computer."
              f"\n         Other people can now join the network through you."
              f"\n         Run with --no-upnp if you would rather it did not."
              f"\nsosa:{node.port}> ", end="", flush=True)
        add_event(node, f"router opened port {node.port}")
    # confirm with an actual peer either way -- some people already forward ports
    for _ in range(3):
        time.sleep(4)
        if not node.peers:
            continue
        if confirm_reachable(node):
            with node.lock:
                url = node.public_url
            print(f"\n  [door] confirmed: the network can reach you at {url}."
                  f"\n         You are now one of the ways in for newcomers."
                  f"\nsosa:{node.port}> ", end="", flush=True)
            add_event(node, "confirmed reachable from the internet")
            return
    if not ok:
        print(f"\n  [door] could not open a port ({detail})."
              f"\n         Mining and sending still work normally -- you just"
              f"\n         cannot host newcomers. That is very common at home."
              f"\nsosa:{node.port}> ", end="", flush=True)


def meet(node, peer):
    if peer == node.my_url or peer in node.peers:
        return False
    if "--isolated" in sys.argv and "127.0.0.1" not in peer and "localhost" not in peer:
        return False          # test mode: only local test peers, never the real node
    node.peers.add(peer)
    node.save_peers()
    introduce_self(node, peer)
    threading.Thread(target=check_peer_rules, args=(node, peer), daemon=True).start()
    threading.Thread(target=sync_once, args=(node,), daemon=True).start()
    return True


def discovery_beacon(node):
    # A cloud server has no local network to shout across. Skipping this on a
    # seed saves a surprising amount of work -- it was burning a full core.
    if getattr(node, "seed_only", False):
        return
    message = f"SOSAIEM2|{node.node_id}|{node.my_url}".encode()
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(message, ("255.255.255.255", DISCOVERY_PORT))
            s.close()
        except Exception:
            pass
        time.sleep(DISCOVERY_INTERVAL)


def discovery_listener(node):
    if getattr(node, "seed_only", False):
        return
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        s.bind(("", DISCOVERY_PORT))
    except Exception as e:
        print(f"  (auto-discovery couldn't start: {e} -- manual 'connect' still works.)")
        return
    while True:
        try:
            data, addr = s.recvfrom(1024)
            parts = data.decode().split("|")
            if len(parts) == 3 and parts[0] == "SOSAIEM2":
                other_id, other_url = parts[1], parts[2]
                if other_id != node.node_id and other_url != node.my_url \
                        and other_url not in node.peers:
                    if meet(node, other_url):
                        print(f"\n  [discovery] found a peer automatically: {other_url}"
                              f"\nsosa:{node.port}> ", end="", flush=True)
        except Exception:
            pass


def _mine_one_block_racing(node):
    # each attempt now costs about 22ms, so batches are small enough that the
    # miner still notices a new block arriving within a second or so
    B_SHARE = 12
    B_BLOCK = 12

    def build_candidate():
        # Everyone who did work in the last few blocks gets paid, not only the
        # people whose share happened to land in the instant before this block
        # was found. Anything already paid by a block on this chain is left out,
        # so nobody is credited twice for the same work.
        already = set()
        tail = node.chain.chain[-(SHARE_WINDOW + 1):]
        for b in tail:
            for tx in b.transactions:
                if isinstance(tx, dict) and tx.get("type") == "shares":
                    for it in (tx.get("list") or []):
                        if isinstance(it, dict):
                            already.add((it.get("address"), it.get("nonce"),
                                         it.get("prev", b.previous_hash)))

        share_list = [{"address": a, "nonce": n}
                      for a in sorted(node.cur_shares["by"])
                      for n in sorted(node.cur_shares["by"][a])
                      if (a, n, prev_hash) not in already]

        # then the older ones, still within the window
        window = {b.compute_hash() for b in node.chain.chain[-(SHARE_WINDOW + 1):-1]}
        for tip, by in list(node.recent_shares.items()):
            if tip not in window:
                continue
            for a in sorted(by):
                for n in sorted(by[a]):
                    if (a, n, tip) not in already:
                        share_list.append({"address": a, "nonce": n, "prev": tip})

        # Cap the share list fairly. A naive share_list[:CAP] drops whatever
        # comes last once the cap is hit -- so when strong miners flood shares, a
        # weak miner's single share gets crowded out and they earn NOTHING despite
        # working ("weak PC left out"). Instead: first give every distinct address
        # ONE slot (so presence guarantees payment), then distribute the remaining
        # slots round-robin across addresses by how many shares they have. This is
        # deterministic (sorted, no randomness) so every fair builder produces the
        # same list, and inclusive so nobody who did real work is dropped.
        _cap = FAIRWORK_MAX_SHARES if fairwork_active(prev.index + 1) else MAX_SHARES_PER_BLOCK
        if len(share_list) > _cap:
            by_addr = {}
            for s in share_list:
                by_addr.setdefault(s["address"], []).append(s)
            # stable order: address, then original order within address
            addrs = sorted(by_addr)
            fair = []
            # round 1: one share per address (guaranteed inclusion)
            for a in addrs:
                if len(fair) >= _cap:
                    break
                fair.append(by_addr[a].pop(0))
            # rounds 2+: round-robin the remainder until the cap is full
            while len(fair) < _cap and any(by_addr[a] for a in addrs):
                for a in addrs:
                    if len(fair) >= _cap:
                        break
                    if by_addr[a]:
                        fair.append(by_addr[a].pop(0))
            share_list = fair
        else:
            share_list = share_list[:_cap]
        counts = {}
        _fw = fairwork_active(prev.index + 1)
        _starget = share_target_at(target, prev.index + 1) if _fw else None
        weights = {}
        for s in share_list:
            counts[s["address"]] = counts.get(s["address"], 0) + 1
            if _fw:
                _at = s.get("prev", prev_hash)
                _hv = int(share_hash(_at, s["address"], s["nonce"]), 16)
                weights[s["address"]] = weights.get(s["address"], 0.0) + \
                    share_difficulty(hex(_hv), _starget)
        reward = round(max(0.0, min(BLOCK_REWARD, remaining_supply(node.chain))), 8)
        txs = []
        # prove this block came from a fair-split build
        txs.append({"type": "version", "v": BUILD_MARKER})
        if share_list:
            txs.append({"type": "shares", "list": share_list})
        if reward > 0:
            # When the forcing rule is in force, the payout is the share-chain's
            # canonical split -- the same one every validator will check against.
            # Below activation, the original in-block split is used and nothing
            # changes. During grace either is accepted; we build the fair one.
            phase = sharechain_phase(prev.index + 1)
            canon = None
            if paylist_active(prev.index + 1):
                # pay across the proof-of-work shares carried in THIS block --
                # the same list every validator verifies and reads, so everyone
                # who worked (and is in the block) is paid, deterministically.
                # At/after the fair-work flag day, split by difficulty-weighted
                # work (matches the validator), so any device is paid for exactly
                # the work it proved.
                if _fw:
                    canon = split_amounts_weighted(reward, weights) if weights else None
                else:
                    canon = split_amounts(reward, counts) if counts else None
            elif phase in ("grace", "hard"):
                # Same anchor-recency set the validator will derive from this
                # same parent block, so the fair split we build matches theirs.
                fresh = (fresh_anchor_hashes(node.chain.chain, prev_hash)
                         if anchor_rule_active(prev.index + 1) else None)
                canon = (canonical_payout_allwork(node.share_chain, reward,
                                                  window=PPLNS_WINDOW, fresh=fresh)
                         if allpay_active(prev.index + 1)
                         else canonical_payout(node.share_chain, reward,
                                               window=PPLNS_WINDOW, fresh=fresh))
            if canon:
                txs += [make_reward(a, amt) for a, amt in sorted(canon.items())]
            elif counts:
                txs += [make_reward(a, amt)
                        for a, amt in sorted(split_amounts(reward, counts).items())]
            else:
                txs.append(make_reward(node.payout_address, reward))

        # Carry pending transfers into the block -- for free -- once activated.
        # Below the activation height this whole section is skipped, so blocks
        # stay transfer-free and the chain behaves exactly as before.
        # Wrapped so that if anything here ever goes wrong, block-building carries
        # on WITHOUT transfers rather than stopping mining. Worst case a transfer
        # waits for the next block; the chain never stalls.
        if transfers_active(prev.index + 1):
            try:
                bal = compute_balances(node.chain)
                for a, amt in (split_amounts(reward, counts).items() if counts else []):
                    bal[a] = round(bal.get(a, 0.0) + amt, 8)   # this block's rewards
                picked = 0
                # deterministic order (by signature) so every miner builds the same set
                for tx in sorted(node.transfers.values(),
                                 key=lambda t: t.get("signature", "")):
                    if picked >= MAX_TRANSFERS_PER_BLOCK:
                        break
                    if tx.get("signature") in node.confirmed:
                        continue
                    if not transfer_is_valid(tx) or not transfer_work_is_valid(tx):
                        continue
                    frm, to, amt = tx.get("from"), tx.get("to"), tx.get("amount")
                    if not amount_is_sane(amt) or amt > bal.get(frm, 0.0) + 1e-9:
                        continue                          # can't afford now -> skip
                    txs.append({"type": "transfer", "from": frm,
                                "from_pubkey": tx.get("from_pubkey"), "to": to,
                                "amount": amt, "timestamp": tx.get("timestamp"),
                                "signature": tx.get("signature"),
                                "work_nonce": tx.get("work_nonce")})
                    bal[frm] = round(bal.get(frm, 0.0) - amt, 8)
                    bal[to] = round(bal.get(to, 0.0) + amt, 8)
                    picked += 1
            except Exception as e:
                # never let transfer handling stop the miner from producing a block
                print(f"   (transfer scoop skipped this block: {e})")
        return Block(prev.index + 1, txs, prev_hash)

    with node.lock:
        node._ensure_share_height()
        prev = node.chain.last_block
        prev_hash = prev.compute_hash()
        target = next_target(node.chain.chain)
        # At/after the fair-work flag day this is the much easier target, so even
        # a very weak device lands shares. Validators use the same height-aware
        # target, so the shares this miner produces are accepted by every updated
        # node. Below the flag day it's exactly the old target -- no change.
        s_target = share_target_at(target, prev.index + 1)
        version = node.cur_shares["version"]
        candidate = build_candidate()

    my_addr = node.payout_address
    ns = int(time.time() * 1e6) & ((1 << 48) - 1)
    fresh_shares = []
    race_start = time.time()
    last_beat = race_start
    last_pull = race_start

    # --- the hashing crew -------------------------------------------------
    # Mining used to run on a single core, so seven eighths of a normal machine
    # sat idle. scrypt is implemented in C and lets go of Python's global lock
    # while it works, so real threads really do run at the same time here --
    # which is unusual for Python and is what makes this worth doing.
    #
    # Only the hashing is parallel. Deciding what to mine, collecting shares and
    # accepting a won block all stay on this one thread, because that is the
    # part where getting the order wrong costs someone their block.
    n_workers = max(1, min(node.mine_threads, 32))
    stop = threading.Event()
    found_box = {"block": None}
    share_box = []
    box_lock = threading.Lock()
    counter = {"hashes": 0}
    gen = {"n": 0, "txs": candidate.transactions}
    # Share-chain production rides the SAME hashing crew: one extra hash per
    # attempt, reusing the nonce, instead of a whole second mining loop. `sc_tip`
    # is refreshed as our shares land so each new one chains onto the latest.
    sc_target = sharechain_target(target)
    sc = {"tip": (node.share_chain.tip or SHARECHAIN_GENESIS),
          "uncles": node.share_chain.uncle_candidates()}
    schain_box = []

    def worker(slot):
        my_gen = -1
        blk = None
        nb = slot
        sn = ns + slot
        while not stop.is_set():
            if gen["n"] != my_gen:
                my_gen = gen["n"]
                blk = Block(prev.index + 1, gen["txs"], prev_hash)
                nb = slot
            # a share attempt
            sn += n_workers
            if int(share_hash(prev_hash, my_addr, sn), 16) < s_target:
                with box_lock:
                    share_box.append(sn)
            # a share-chain attempt -- one extra hash, reusing this same nonce,
            # so the share-chain fills at the natural rate with no second loop
            sc_id = sharechain_share_id(sc["tip"], prev_hash, my_addr, sn,
                                        sc["uncles"])
            if int(sc_id, 16) < sc_target:
                with box_lock:
                    schain_box.append({"share_prev": sc["tip"],
                                       "block_prev": prev_hash,
                                       "address": my_addr, "nonce": sn,
                                       "uncles": sc["uncles"],
                                       "id": sc_id})
            # a block attempt -- every worker walks a different lane of nonces
            blk.nonce = nb
            if int(blk.pow_hash(), 16) < target:
                with box_lock:
                    if found_box["block"] is None:
                        found_box["block"] = blk
                stop.set()
                return
            nb += n_workers
            with box_lock:
                counter["hashes"] += 3

    crew = [threading.Thread(target=worker, args=(i,), daemon=True)
            for i in range(n_workers)]
    for t in crew:
        t.start()

    def shut_down():
        stop.set()
        for t in crew:
            t.join(timeout=1.0)
    while True:
        now = time.time()
        # The miner maxes the CPU, which can starve the background sync thread
        # so badly that this node keeps building on a stale tip and every block
        # it wins is already orphaned. So pull the network's tip ourselves every
        # couple of seconds -- if a longer chain exists, adopt it and abandon
        # this now-pointless attempt immediately.
        if now - last_pull > 2:
            last_pull = now
            # No network calls here, ever. This loop is the mining thread, and
            # anything that waits on a peer stops the machine from hashing --
            # four peers with a three second timeout each meant it could sit
            # idle for longer than it spent working. The background sync thread
            # keeps the chain current; all this needs is a free memory read to
            # notice when the tip has moved under it.
            if node.chain.last_block.compute_hash() != prev_hash:
                shut_down()
                return None
        if now - last_beat > 15:
            queued = sum(len(v) for v in node.cur_shares["by"].values())
            # memory-hard attempts run in the tens per second, not the thousands,
            # so kH/s would just read as zero and look broken
            rate = hashes_done / max(now - race_start, 0.001)
            print(f"   ...still working on block {prev.index + 1} "
                  f"({int(now - race_start)}s, ~{rate:.0f} hashes/s, "
                  f"{queued} work-share(s) queued for this block)")
            last_beat = now

        # collect whatever the crew has turned up since the last pass
        with box_lock:
            fresh_shares = share_box[:]
            share_box.clear()
            found_block = found_box["block"]
            hashes_done = counter["hashes"]

        with node.lock:
            if node.chain.last_block.compute_hash() != prev_hash:
                shut_down()
                return None
            for n0 in fresh_shares:
                node._add_share(my_addr, n0)
            if node.cur_shares["version"] != version:
                version = node.cur_shares["version"]
                candidate = build_candidate()
                # hand the crew the new contents; they rebuild and carry on
                gen["txs"] = candidate.transactions
                gen["n"] += 1
        for n0 in fresh_shares:
            gossip(node, "/share",
                   {"prev_hash": prev_hash, "address": my_addr, "nonce": n0})
        # Drain the share-chain shares the crew turned up (one hash each, no
        # separate mining loop) -- add and relay them, then advance our tip so
        # the next ones chain onto the newest. Dormant-safe: this only builds
        # the record; nothing depends on it until the forcing rule activates.
        with box_lock:
            fresh_sc = schain_box[:]
            schain_box.clear()
        for sh in fresh_sc:
            try:
                handle_incoming_schain_share(node, sh)
            except Exception:
                pass
        with node.lock:
            cur_tip = node.share_chain.tip or SHARECHAIN_GENESIS
        if cur_tip != sc["tip"]:
            # The tip moved -- our share landed, or someone else's arrived over
            # the network. Rebase IMMEDIATELY so we don't keep mining on a
            # stale tip that will only orphan. Only rebasing when our own share
            # landed was exactly how a smaller miner's whole output turned into
            # invisible orphans while a faster miner extended the chain.
            with node.lock:
                sc["tip"] = node.share_chain.tip or SHARECHAIN_GENESIS
                sc["uncles"] = node.share_chain.uncle_candidates()
        fresh_shares = []

        found = found_block is not None
        if found:
            candidate = found_block
        else:
            time.sleep(0.05)      # let the crew work; this thread only steers

        won = None
        with node.lock:
            if not node.mining:
                shut_down()
                return None
            if node.chain.last_block.compute_hash() != prev_hash:
                shut_down()
                return None
            if found:
                node.chain.chain.append(candidate)
                node.save_chain()
                node._ensure_share_height()
                node.retally()
                won = candidate
            elif node.cur_shares["version"] != version:
                version = node.cur_shares["version"]
                candidate = build_candidate()
                gen["txs"] = candidate.transactions
                gen["n"] += 1
        if won:
            shut_down()
            return won


def mining_watchdog(node):
    """
    Catch the "mining on an invalid chain without noticing" failure.

    The mining loop only reacts to our LOCAL tip moving; it trusts the background
    sync to have already pulled any better network chain. But on a flaky link (a
    throttled seed timing out, peers behind home routers) that sync can quietly
    fail for minutes -- so the miner keeps extending its own island, the node
    still reports "synced", and every block it wins is orphaned the moment it
    finally reconnects. Users saw this as "mine for a while, then lose everything
    on resync."

    This watchdog runs independently: every ~15s it asks peers directly for their
    height, and if ANY peer reports a chain meaningfully ahead of ours that we
    have NOT adopted, it (a) marks us not-synced so the UI stops claiming we're
    fine and mining pauses, and (b) forces a fresh chain pull. It never trusts a
    single local read -- it goes and asks the network.
    """
    if getattr(node, "seed_only", False):
        return
    while True:
        time.sleep(15)
        try:
            peers = list(node.peers)
            if not peers:
                continue
            with node.lock:
                mine = len(node.chain.chain)
            best_seen = 0
            best_peer = None
            for p in peers[:6]:
                info = get_json(p.rstrip("/") + "/info", timeout=4)
                if info and isinstance(info.get("blocks"), int):
                    if info["blocks"] > best_seen:
                        best_seen = info["blocks"]
                        best_peer = p
            # Two danger signs, both handled by pulling the peer's chain and
            # letting is_better (heaviest-work) decide:
            #   (a) a peer is clearly AHEAD of us -> we're behind, catch up.
            #   (b) we are AHEAD of every peer while mining -> we may be on a
            #       PRIVATE fork (we mined blocks the network never accepted).
            #       This is the "mined coins vanish on resync" case: our own
            #       chain looks longest to us, so nothing pulls us back. Compare
            #       against the peer's chain directly; if theirs is heavier,
            #       is_better adopts it and our orphaned blocks (and their phantom
            #       rewards) correctly disappear.
            ahead_of_all = best_seen and best_seen < mine
            behind = best_seen and best_seen > mine + 2
            if behind or ahead_of_all:
                node.has_synced = False
                node.watchdog_resyncs = getattr(node, "watchdog_resyncs", 0) + 1
                add_event(node, f"reconciling with network (mine {mine}, net {best_seen})")
                try:
                    sync_chain(node)
                except Exception:
                    pass
                with node.lock:
                    # synced again if we now agree with the network's height
                    if best_seen and abs(len(node.chain.chain) - best_seen) <= 2:
                        node.has_synced = True
        except Exception:
            pass


def mining_loop(node):
    node.mine_stats = {"start": time.time(), "earned": 0.0, "blocks": 0}
    last_tick = time.time()
    me = node.payout_address
    while node.mining:
        now = time.time()
        if now - last_tick > 120:
            print(f"   (long pause detected: {int(now - last_tick)}s -- "
                  f"session stats reset)")
            node.mine_stats = {"start": now, "earned": 0.0, "blocks": 0}
        last_tick = now
        if remaining_supply(node.chain) <= 0:
            print("   cap reached -- all 12,212,010 SOSA now exist. Mining is done;")
            print("   transfers continue by vote, feeless, forever.")
            add_event(node, "supply cap reached -- mining complete")
            node.mining = False
            break
        block = _mine_one_block_racing(node)
        if block is None:
            continue
        my_cut = round(sum(tx.get("amount", 0) for tx in block.transactions
                           if isinstance(tx, dict) and tx.get("type") == "reward"
                           and tx.get("to") == me), 8)
        paid = sum(1 for tx in block.transactions
                   if isinstance(tx, dict) and tx.get("type") == "reward")
        node.mine_stats["earned"] = round(node.mine_stats["earned"] + my_cut, 8)
        node.mine_stats["blocks"] += 1
        threading.Thread(target=broadcast_block, args=(node, block), daemon=True).start()
        threading.Thread(target=push_chain_once, args=(node,), daemon=True).start()
        elapsed = time.time() - node.mine_stats["start"]
        rate_hr = (node.mine_stats["earned"] / elapsed * 3600) if elapsed > 0 else 0
        add_event(node, f"won block {len(node.chain.chain) - 1}: +{my_cut:.6f} SOSA "
                        f"({paid} miner(s) paid)")
        print(f"\n   won block {len(node.chain.chain) - 1}: my slice +{my_cut:.6f} SOSA "
              f"({paid} miner(s) paid)   | session {node.mine_stats['earned']:.4f} "
              f"in {elapsed:.0f}s | ~{rate_hr:.1f} SOSA/hour"
              f"\nsosa:{node.port}> ", end="", flush=True)
    st = node.mine_stats
    print(f"\n  Mining stopped. Won {st['blocks']} block(s), earned {st['earned']:.4f} SOSA."
          f"\nsosa:{node.port}> ", end="", flush=True)
    node.save_chain()


def start_mining(node):
    if getattr(node, "seed_only", False):
        return ("this node is running in seed mode -- it hosts the chain for\n"
                "   everyone else and deliberately does no mining.")
    if node.mining:
        return "already mining -- type 'stop' to stop."
    # Don't let a fresh miner strike blocks on its lone genesis chain before it
    # has caught up to the network. If we know about peers but haven't synced to
    # their (longer/heavier) chain yet, mining now would just build a dead fork
    # from block 1 -- exactly the "it started from genesis and mined its own
    # chain" bug. Try one inline sync; if we're still tiny while peers exist,
    # hold off and tell the user to wait a moment.
    with node.lock:
        have_peers = len(node.peers) > 0
        height = len(node.chain.chain)
    if have_peers and not getattr(node, "has_synced", False):
        try:
            sync(node)
            node.has_synced = True
        except Exception:
            pass
        with node.lock:
            height = len(node.chain.chain)
        if height <= 1:
            return ("still catching up to the network -- not mining yet so you\n"
                    "   don't build your own dead fork. Give it a few seconds for\n"
                    "   the chain to sync, then press start again.")
    node.mining = True
    threading.Thread(target=mining_loop, args=(node,), daemon=True).start()
    add_event(node, "mining started")
    return ("mining started in the background (real proof-of-work; CPU works hard).\n"
            "   Difficulty auto-adjusts: ~60s/block, ~100 SOSA/hour NETWORK-WIDE,\n"
            "   every active miner earning a slice of every block by proven work.\n"
            "   Type 'stop' to stop. Transfers settle in the next block or two.")


def stop_mining(node):
    if not node.mining:
        return "not mining."
    node.mining = False
    add_event(node, "mining stopped")
    return "stopping (finishing the current attempt)..."


def do_send(node, to, amount):
    if not to.startswith("SOSA"):
        return False, "that doesn't look like a SOSA address."
    with node.lock:
        balances = node.get_balances()
        me = node.wallet.address()
        available = balances.get(me, 0) - node._committed_outgoing(me, None)
    if amount <= 0:
        return False, "amount must be positive."
    if amount > available + 1e-9:
        return False, f"not enough SOSA (available {available:.8f})."
    tx = make_transfer(node.wallet, to, round(amount, 8))
    if transfers_active(len(node.chain.chain)):
        # Chain-settled transfer: do the send-time work, then broadcast for a
        # miner to carry into a block. Works even if the recipient (or every
        # other holder) is offline -- no live voting needed.
        tx = stamp_transfer(tx)
        with node.lock:
            node.transfers[tx["signature"]] = tx
        add_event(node, f"sent {amount} SOSA -> {to[:10]}...")
        gossip(node, "/tx", tx)
        return True, (f"sent {amount} SOSA -> {to[:16]}...  "
                      "(feeless -- settles in the next block or two)")
    # Dormant (pre-activation): unchanged stake-vote settlement.
    with node.lock:
        node.transfers[tx["signature"]] = tx
    add_event(node, f"sent {amount} SOSA -> {to[:10]}...")
    gossip(node, "/tx", tx)
    cast_vote(node, tx)
    msg = f"sent {amount} SOSA -> {to[:16]}...  (feeless -- confirming by stake vote)"
    if tx["signature"] not in node.confirmed:
        msg += "  [awaiting validator votes -- self-heals within seconds]"
    return True, msg


def show_status(node):
    with node.lock:
        balances = node.get_balances()
        me = node.wallet.address()
        my_bal = balances.get(me, 0)
        total = node.total_stake(balances)
        pend = [(sig, tx) for sig, tx in node.transfers.items()
                if sig not in node.confirmed]
        pend_out = sum(tx.get("amount", 0) for _, tx in pend if tx.get("from") == me)

        def yes_pct(sig):
            yes = sum(max(balances.get(a, 0), 0.0)
                      for a, v in node.votes.get(sig, {}).items()
                      if v.get("approve") and a in node.registry)
            return (100 * yes / total) if total > 0 else 0.0

        print(f"\n  SOSAIEM NODE :{node.port}   {node.my_url}")
        print(f"   my address   : {me}")
        print(f"   my balance   : {my_bal:.8f} SOSA  (this is also my voting weight)")
        if pend_out > 0:
            print(f"   available    : {my_bal - pend_out:.8f} SOSA  "
                  f"({pend_out:.8f} in sends awaiting votes)")
        print(f"   blocks       : {len(node.chain.chain)}  "
              f"| minted {total_minted(node.chain):.4f} / {MAX_SUPPLY} SOSA")
        print(f"   transfers    : {len(node.confirmed)} confirmed by vote (feeless)"
              + (f" | {len(pend)} awaiting votes" if pend else ""))
        for sig, tx in pend[:5]:
            print(f"      awaiting: {tx.get('amount')} SOSA  "
                  f"{tx.get('from','?')[:12]}... -> {tx.get('to','?')[:12]}...  "
                  f"(YES so far: {yes_pct(sig):.0f}% of stake, needs >50%)")
        print(f"   validators   : {len(node.registry)} known "
              f"| total online stake {total:.8f} SOSA")
        print(f"   peers        : {len(node.peers)}")
        holders = {a: b for a, b in sorted(balances.items(), key=lambda kv: -kv[1])
                   if b > 1e-9}
        if holders:
            print(f"   holders:")
            for a, b in list(holders.items())[:10]:
                pct = (100 * b / total) if total > 0 else 0
                tag = "  <- me" if a == me else ""
                print(f"      {a[:18]}...  {b:12.8f} SOSA  ({pct:4.1f}% of stake){tag}")


HELP = """
  Commands:
    mine                 start mining in the background (every miner earns each block)
    stop                 stop mining
    send <addr> <amt>    send SOSA -- feeless, confirmed by stake vote in ~a second
    status               balances, stake weights, validators, peers
    connect <url>        meet a node manually, e.g. connect http://203.0.113.7:7000
    peers                list peers        sync    force a sync now
    chain                show the blockchain tip
    help / quit

  Browser wallet: open http://localhost:<port> on this computer.
  Worldwide:      put one reachable node's URL in seeds.txt (one per line) --
                  peer exchange then pulls you into everyone that node knows.
"""


def main():
    _unfreeze_windows_console()
    port = 7000
    for arg in sys.argv[1:]:
        if arg.isdigit():
            port = int(arg)
    if "--no-browser" not in sys.argv:
        def _open_wallet():
            time.sleep(1.5)
            try:
                import webbrowser
                webbrowser.open(f"http://localhost:{port}")
            except Exception:
                pass
        threading.Thread(target=_open_wallet, daemon=True).start()
    print("=" * 66)
    print("  SOSAIEM -- society's coin  (unified node)")
    print(f"  build {NODE_VERSION}  *  consensus rules v{PROTOCOL_VERSION}")
    print("  mining creates SOSA * stake-voting moves it, feeless * one ledger")
    print("=" * 66)
    node = Node(port)
    start_server(node)
    threading.Thread(target=auto_sync_loop, args=(node,), daemon=True).start()
    threading.Thread(target=rebroadcast_transfers, args=(node,), daemon=True).start()
    threading.Thread(target=mining_watchdog, args=(node,), daemon=True).start()
    if "--isolated" not in sys.argv:      # test mode: no LAN discovery -> stays sealed off
        threading.Thread(target=discovery_beacon, args=(node,), daemon=True).start()
        threading.Thread(target=discovery_listener, args=(node,), daemon=True).start()
    print(f"  This node's address: {node.wallet.address()}")
    print(f"  Browser wallet:      http://localhost:{port}   (dashboard, send, mine)")
    print("  Other Sosaiem nodes on this machine/wifi will be found automatically.")
    load_seeds(node)
    node.no_upnp = "--no-upnp" in sys.argv
    node.no_nostr = "--no-nostr" in sys.argv
    node.seed_only = ("--seed-only" in sys.argv) or ("--seed" in sys.argv)
    # TEST ONLY: keep this node off the real network -- it will only talk to
    # peers handed to it with --peer=... . Lets a two-node test run in isolation.
    node.isolated = "--isolated" in sys.argv
    # TEST ONLY: turn transfers on for this node so a two-node local test can run
    # without editing code. Do NOT use on the real network -- mainnet activation
    # must be by a shared block height so every node switches together.
    if "--transfers-now" in sys.argv:
        globals()["TRANSFERS_ACTIVATION_HEIGHT"] = 0
        print("   [test mode] transfers activated on this node (--transfers-now)")
    for arg in sys.argv[1:]:
        if arg.startswith("--public-url="):
            u = arg.split("=", 1)[1].strip().rstrip("/")
            if is_public_url(u):
                node.public_url = u
                node.reachable = True
                print(f"  Announcing as {u} -- newcomers can find this node "
                      f"through the public relays.")
    for arg in sys.argv[1:]:
        if arg.startswith("--threads="):
            try:
                node.mine_threads = max(1, min(32, int(arg.split("=", 1)[1])))
            except ValueError:
                pass
    if "--isolated" not in sys.argv:
        threading.Thread(target=open_the_door, args=(node,), daemon=True).start()
        threading.Thread(target=retry_bootstrap, args=(node,), daemon=True).start()
        threading.Thread(target=seed_keeper, args=(node,), daemon=True).start()
        threading.Thread(target=nostr_announce_loop, args=(node,), daemon=True).start()
        threading.Thread(target=nostr_discover_loop, args=(node,), daemon=True).start()

    # When there is no keyboard attached -- running under systemd, in a
    # container, piped from anything -- there is no console to read. Reading
    # stdin here would hit EOF instantly and quit, which is why the old service
    # file wrapped this in "sleep infinity |". That wrapper made bash the main
    # process, so when this node died systemd saw a healthy bash and never
    # restarted anything: the node stayed dead until someone noticed by hand.
    # Idling here instead lets systemd own the process directly and restart it
    # the moment it actually crashes.
    if not sys.stdin or not sys.stdin.isatty():
        print("  Running headless (no console). Ctrl-C or systemctl stop to end.")
        while True:
            time.sleep(3600)

    print(HELP)
    while True:
        try:
            raw = input(f"sosa:{node.port}> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  bye."); break
        if not raw:
            continue
        p = raw.split()
        c = p[0].lower()
        try:
            if c == "mine":
                if len(p) > 1 and p[1].lower() == "stop":
                    print("   " + stop_mining(node))
                else:
                    print("   " + start_mining(node))
            elif c == "stop":
                print("   " + stop_mining(node))
            elif c == "send" and len(p) >= 3:
                try:
                    ok, msg = do_send(node, p[1], float(p[2]))
                    print("   " + msg)
                except ValueError:
                    print("   amount must be a number.")
            elif c == "status":
                show_status(node)
            elif c == "connect" and len(p) > 1:
                if meet(node, p[1]):
                    print(f"   met {p[1]}")
                else:
                    print("   already known (or that's me).")
            elif c == "peers":
                for peer in sorted(node.peers):
                    print(f"   {peer}")
                if not node.peers:
                    print("   (no peers yet)")
            elif c == "sync":
                sync(node); print("   synced.")
            elif c == "chain":
                with node.lock:
                    tip = node.chain.last_block
                    print(f"   {len(node.chain.chain)} blocks; tip #{tip.index} "
                          f"hash {tip.compute_hash()[:20]}...")
            elif c == "help":
                print(HELP)
            elif c == "quit":
                print("  bye."); break
            else:
                print("   unknown -- type 'help'")
        except KeyboardInterrupt:
            print()


if __name__ == "__main__":
    main()
