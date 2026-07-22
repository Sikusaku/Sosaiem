"""Sosaiem node: mining, feeless stake-voting transfers, and P2P networking."""

import sys
import os
import json
import time
import uuid
import socket
import hashlib
import threading
import collections
import urllib.parse
import urllib.request

import portmap
import nostrseed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer as _BaseHTTPServer


class ThreadingHTTPServer(_BaseHTTPServer):
    # Set at class level so it takes effect *before* the socket binds. This is
    # what frees the port the moment the app closes; without it Windows holds
    # the port for a minute or two and reopening the wallet fails to start.
    allow_reuse_address = True
    daemon_threads = True

from wallet import Wallet, verify_signature
from blockchain import (Blockchain, Block, next_target, compute_targets,
                        MAX_TARGET, memory_hard)
from coin import (compute_balances, total_minted, remaining_supply,
                  make_transfer, make_reward, transfer_is_valid, amount_is_sane,
                  _address_from_pubkey, BLOCK_REWARD, MAX_SUPPLY,
                  TARGET_BLOCK_SECONDS)


SYNC_INTERVAL = 3

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
PROTOCOL_VERSION = 2
NODE_VERSION = "2.0.1"
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


def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


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


def _check_block_content(transactions, prev_hash, share_target):
    shares_entries = []
    rewards = []
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
        else:
            return False, 0.0
    if len(shares_entries) > 1:
        return False, 0.0

    counts = {}
    if shares_entries:
        lst = shares_entries[0].get("list", [])
        if not isinstance(lst, list) or len(lst) > MAX_SHARES_PER_BLOCK:
            return False, 0.0
        seen = set()
        for s in lst:
            if not isinstance(s, dict):
                return False, 0.0
            addr, nonce = s.get("address"), s.get("nonce")
            if not isinstance(addr, str) or not addr.startswith("SOSA") \
                    or not isinstance(nonce, int):
                return False, 0.0
            if (addr, nonce) in seen:
                return False, 0.0
            seen.add((addr, nonce))
            if int(share_hash(prev_hash, addr, nonce), 16) >= share_target:
                return False, 0.0
            counts[addr] = counts.get(addr, 0) + 1

    block_reward = round(sum(tx["amount"] for tx in rewards), 8)
    if rewards:
        if counts:
            expected = split_amounts(block_reward, counts)
            got = {}
            for tx in rewards:
                if tx["to"] in got:
                    return False, 0.0
                got[tx["to"]] = round(tx["amount"], 8)
            if set(got) != set(expected):
                return False, 0.0
            for addr, amt in expected.items():
                if abs(got[addr] - amt) > 1e-7:
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
_verified_work = set()
_VERIFIED_CAP = 200000


def _remember_verified(block_id):
    if len(_verified_work) >= _VERIFIED_CAP:
        _verified_work.clear()
    _verified_work.add(block_id)


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
    for block in chain.chain:
        if block.index == 0:
            continue
        bid = block.compute_hash()
        if bid in _verified_work:
            # we have already re-done this block's work; still count its reward
            for tx in block.transactions:
                if isinstance(tx, dict) and tx.get("type") == "reward":
                    minted += tx.get("amount", 0.0)
            continue
        ok, block_reward = _check_block_content(
            block.transactions, block.previous_hash, share_target_for(targets[block.index]))
        if not ok:
            return False
        if block_reward > BLOCK_REWARD + 1e-6:
            return False
        minted += block_reward
        _remember_verified(bid)
    if minted > MAX_SUPPLY + 1e-6:
        return False
    return True


def validate_new_block(chain, block):
    if block.previous_hash != chain.last_block.compute_hash():
        return False
    if block.index != chain.last_block.index + 1:
        return False
    target = next_target(chain.chain)
    if int(block.pow_hash(), 16) >= target:
        return False
    ok, block_reward = _check_block_content(
        block.transactions, block.previous_hash, share_target_for(target))
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


def is_better(candidate, current):
    lc, cc = len(candidate.chain), len(current.chain)
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
    def __init__(self, port):
        self.port = port
        self.node_id = uuid.uuid4().hex[:8]
        self.my_url = f"http://{get_lan_ip()}:{port}"
        self.chain_file = f"chain_{port}.json"
        self.wallet_file = f"wallet_{port}.pem"
        self.peers_file = f"peers_{port}.json"
        self.transfers_file = f"transfers_{port}.json"
        self.validators_file = f"validators_{port}.json"

        self.wallet = self._load_or_create_wallet()
        self.chain = self._load_chain()
        self.peers = self._load_peers()
        self.lock = threading.Lock()

        self.registry = {self.wallet.address(): {"pubkey": self.wallet.public_key_hex()}}

        self.transfers = {}

        self.votes = {}

        self.confirmed_log = []
        self.confirmed = set()

        self.mining = False
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
        self._load_validators()
        self._load_transfers()
        if self.peers:
            print(f"  Remembered {len(self.peers)} peer(s) from last time.")

    def _load_or_create_wallet(self):
        if os.path.exists(self.wallet_file):
            w = Wallet.load_from_file(self.wallet_file)
            print(f"  Loaded wallet: {w.address()}")
            if not w.has_phrase():
                print("  (this wallet predates recovery phrases -- it has no backup words.")
                print("   to get a recoverable wallet, make a new one and send your SOSA to it.)")
        else:
            try:
                w, phrase = Wallet.create_with_phrase()
                w.save_to_file(self.wallet_file)
                print(f"  New wallet: {w.address()}")
                print("\n  ================= WRITE THESE WORDS DOWN =================")
                for i in range(0, len(phrase.split()), 6):
                    print("    " + " ".join(phrase.split()[i:i + 6]))
                print("  These 17 words are the only way back to this wallet if you")
                print("  lose this computer. Anyone who reads them owns your coins.")
                print("  =========================================================\n")
            except Exception as e:
                # a wallet that works beats no wallet -- but say so plainly
                w = Wallet(); w.save_to_file(self.wallet_file)
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
            if validate_full_chain(chain):
                print(f"  Loaded chain: {len(chain.chain)} blocks.")
                return chain
        except Exception:
            pass
        print("  Saved chain invalid -- starting fresh.")
        return Blockchain()

    def save_chain(self):
        with open(self.chain_file, "w") as f:
            json.dump(chain_to_list(self.chain), f)

    def _load_peers(self):
        if not os.path.exists(self.peers_file):
            return set()
        try:
            with open(self.peers_file) as f:
                saved = set(json.load(f))
            saved.discard(self.my_url)
            return saved
        except Exception:
            return set()

    def save_peers(self):
        try:
            with open(self.peers_file, "w") as f:
                json.dump(sorted(self.peers), f)
        except Exception:
            pass

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
        for entry in log:
            tx, votes = entry.get("tx", {}), entry.get("votes", {})
            sig = tx.get("signature")
            if not sig or sig in self.confirmed or not transfer_is_valid(tx):
                continue
            if not all(vote_is_valid(v) for v in votes.values()):
                continue
            # Re-check that these votes really were a stake majority. The file
            # on disk is just a cache -- if it is stale, edited or corrupted it
            # must not be able to hand anyone coins on the next start-up.
            good = {a: v for a, v in votes.items()
                    if v.get("tx_signature") == sig and v.get("validator") == a}
            balances = compute_balances(self.chain)
            total = sum(max(b, 0.0) for b in balances.values())
            yes = sum(max(balances.get(a, 0), 0.0)
                      for a, v in good.items() if v.get("approve"))
            if total <= 0 or yes * 2 <= total:
                continue
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
        for entry in self.confirmed_log:
            tx = entry["tx"]
            balances[tx["from"]] = balances.get(tx["from"], 0) - tx["amount"]
            balances[tx["to"]] = balances.get(tx["to"], 0) + tx["amount"]
        return {a: round(b, 8) for a, b in balances.items()}

    def total_stake(self, balances=None):
        balances = balances if balances is not None else self.get_balances()
        return sum(max(balances.get(a, 0), 0.0) for a in self.registry)

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
        for addr, vote in self.votes.get(sig, {}).items():
            if vote.get("approve") and addr in self.registry:
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


def post_json(url, obj, timeout=3):
    try:
        data = json.dumps(obj).encode()
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return loads_strict(r.read())
    except Exception:
        return None


def get_json(url, timeout=5):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return loads_strict(r.read())
    except Exception:
        return None


def gossip(node, path, obj):
    for peer in list(node.peers):
        threading.Thread(target=post_json, args=(peer.rstrip("/") + path, obj),
                         daemon=True).start()


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
    with node.lock:
        pending = [tx for sig, tx in node.transfers.items()
                   if sig not in node.confirmed]
    for tx in pending:
        cast_vote(node, tx)


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
        return {"address": me,
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
            if self.path in ("/", "/dashboard"):
                if not self._local():
                    self._json({"error": "the wallet dashboard answers only on "
                                         "the node's own computer (localhost)"}, 403)
                    return
                try:
                    body = DASHBOARD_HTML.encode()
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
            elif self.path == "/chain":
                with node.lock:
                    self._json(chain_to_list(node.chain))
            elif self.path == "/state":
                with node.lock:
                    self._json({"registry": node.registry, "log": node.confirmed_log,
                                "url": node.public_url or node.my_url})
            elif self.path == "/info":
                with node.lock:
                    self._json({"blocks": len(node.chain.chain),
                                "confirmed": len(node.confirmed),
                                "last_hash": node.chain.last_block.compute_hash(),
                                "protocol": PROTOCOL_VERSION,
                                "version": NODE_VERSION,
                                "genesis": _CANONICAL_GENESIS_HASH})
            elif self.path == "/network":
                # Compact public summary for the live mint page. Small and cheap
                # to serve no matter how long the chain gets -- the page must
                # never have to pull the whole chain just to show activity.
                with node.lock:
                    blocks = list(node.chain.chain)
                    minted = total_minted(node.chain)
                earned = {}
                won = {}
                for b in blocks[1:]:
                    for tx in b.transactions:
                        if isinstance(tx, dict) and tx.get("type") == "reward":
                            a = tx.get("to")
                            earned[a] = round(earned.get(a, 0.0) + tx.get("amount", 0.0), 8)
                            won[a] = won.get(a, 0) + 1
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
                roll = sorted(({"a": a, "n": n, "blocks": won.get(a, 0)}
                               for a, n in earned.items()),
                              key=lambda r: -r["n"])[:25]
                self._json({"blocks": len(blocks), "minted": round(minted, 8),
                            "max_supply": MAX_SUPPLY, "miners": len(earned),
                            "active": active, "recent": recent, "roll": roll,
                            "protocol": PROTOCOL_VERSION, "version": NODE_VERSION})

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
                # invisible to anyone browsing.
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                sig_want = (q.get("sig", [""])[0] or "").strip()
                with node.lock:
                    balances = node.get_balances()
                    out = []
                    for entry in reversed(node.confirmed_log[-200:]):
                        tx = entry.get("tx", {})
                        sig = tx.get("signature", "")
                        if sig_want and not sig.startswith(sig_want):
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
                        if len(out) >= (1 if sig_want else 40):
                            break
                    pending = [{"from": t.get("from"), "to": t.get("to"),
                                "amount": t.get("amount"), "signature": s}
                               for s, t in node.transfers.items()
                               if s not in node.confirmed][:20]
                self._json({"confirmed": out, "pending": pending})

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
                    for entry in node.confirmed_log[-400:]:
                        tx = entry.get("tx", {})
                        if tx.get("from") == a or tx.get("to") == a:
                            moves.append({"dir": "out" if tx.get("from") == a else "in",
                                          "amount": tx.get("amount"),
                                          "other": tx.get("to") if tx.get("from") == a
                                                   else tx.get("from"),
                                          "t": tx.get("timestamp")})
                    self._json({
                        "address": a,
                        "balance": round(node.get_balances().get(a, 0.0), 8),
                        "mined": round(mined, 8),
                        "blocks_paid": blocks_paid,
                        "first_block": first, "last_block": last,
                        "transfers": moves[-25:][::-1],
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
                msg = start_mining(node) if body.get("on") else stop_mining(node)
                self._json({"ok": True, "mining": node.mining,
                            "message": msg.split("\n")[0]})

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

            elif self.path == "/vote":
                self._json({"result": handle_incoming_vote(node, body)})

            else:
                self._json({"error": "unknown"}, 404)

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
    with node.lock:
        node._ensure_share_height()
        if prev_hash != node.cur_shares["prev"]:
            return "stale"
        st = share_target_for(next_target(node.chain.chain))
        if int(share_hash(prev_hash, addr, nonce), 16) >= st:
            return "invalid"
        fresh = node._add_share(addr, nonce)
    if fresh:
        gossip(node, "/share", s)
        return "accepted"
    return "duplicate"


def handle_incoming_block(node, block):
    accepted = False
    need_sync = False
    with node.lock:
        last = node.chain.last_block
        if block.index <= last.index:
            pass
        elif block.index == last.index + 1 and validate_new_block(node.chain, block):
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
        threading.Thread(target=push_chain, args=(node,), daemon=True).start()
        with node.lock:
            newly = node.retally()
        for sig in newly:
            announce_confirm(node, sig)
        return "accepted"
    if need_sync:
        threading.Thread(target=sync, args=(node,), daemon=True).start()
        return "resync"
    return "duplicate"


def broadcast_block(node, block):
    payload = block_to_dict(block)
    for peer in list(node.peers):
        post_json(peer.rstrip("/") + "/block", payload)


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
        if n > peer_blocks:
            with node.lock:
                payload = chain_to_list(node.chain)
            post_json(base + "/submit_chain", payload)


def handle_submit_chain(node, data):
    """A peer pushed its chain to us. Adopt it if it's valid and better, then
    relay it onward to our reachable peers (unreachable ones pull it themselves)."""
    try:
        cand = list_to_chain(data)
    except Exception:
        return "bad"
    with node.lock:
        # fast reject: only a strictly longer chain can win, so don't pay for
        # full validation of same/shorter chains that get pushed constantly
        if len(cand.chain) <= len(node.chain.chain):
            return "kept"
    if not validate_full_chain(cand):
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
        print(f"\n  [relay] adopted a pushed chain -> {len(cand.chain)} blocks"
              f"\nsosa:{node.port}> ", end="", flush=True)
        with node.lock:
            newly = node.retally()
        for sig in newly:
            announce_confirm(node, sig)
        # relay onward to reachable peers; home nodes get it via their own pull
        threading.Thread(target=push_chain, args=(node,), daemon=True).start()
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
    print(f"\n  [tx] transfer received -- validators are voting..."
          f"\nsosa:{node.port}> ", end="", flush=True)
    gossip(node, "/tx", tx)
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
        threading.Thread(target=sync, args=(node,), daemon=True).start()
    return "ok"


def sync_chain(node):
    if not node.peers:
        return
    best, source = node.chain, None
    for peer in list(node.peers):
        data = get_json(peer.rstrip("/") + "/chain")
        if data is None:
            continue
        cand = list_to_chain(data)
        if not validate_full_chain(cand):
            continue
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
            switched = True
    if switched:
        print(f"\n  [sync] adopted a better chain from {source} "
              f"-> {len(best.chain)} blocks\nsosa:{node.port}> ", end="", flush=True)
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
                total = node.total_stake(balances)
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


def sync(node):
    sync_chain(node)
    sync_transfers(node)
    revote_pending(node)
    push_chain(node)          # shove our blocks OUT so unreachable miners still count


def auto_sync_loop(node):
    tick = 0
    # sync once immediately so a fresh miner builds on the network's tip
    # instead of starting its own island from genesis
    try:
        sync(node)
    except Exception:
        pass
    while True:
        time.sleep(SYNC_INTERVAL)
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
            if url and url != node.my_url and url not in node.peers:
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


def good_seeds(node, verify=False, limit=20):
    """
    The entry points this node would recommend to a newcomer: public addresses,
    running our coin, that were actually answering recently.
    """
    with node.lock:
        candidates = [p for p in node.peers if is_public_url(p)]
        if node.reachable and node.public_url and is_public_url(node.public_url):
            candidates.append(node.public_url)
    seen, out = set(), []
    for url in candidates:
        u = url.rstrip("/")
        if u in seen:
            continue
        seen.add(u)
        if verify and not _answers(u, timeout=3):
            continue
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
    """
    delay = 30
    while True:
        time.sleep(delay)
        with node.lock:
            alone = not node.peers
        if not alone:
            delay = 30
            continue
        if load_seeds(node):
            return
        delay = min(delay * 2, 600)      # back off, but never give up


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
    node.peers.add(peer)
    node.save_peers()
    introduce_self(node, peer)
    threading.Thread(target=check_peer_rules, args=(node, peer), daemon=True).start()
    threading.Thread(target=sync, args=(node,), daemon=True).start()
    return True


def discovery_beacon(node):
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
        share_list = [{"address": a, "nonce": n}
                      for a in sorted(node.cur_shares["by"])
                      for n in sorted(node.cur_shares["by"][a])]

        share_list = share_list[:MAX_SHARES_PER_BLOCK]
        counts = {}
        for s in share_list:
            counts[s["address"]] = counts.get(s["address"], 0) + 1
        reward = round(max(0.0, min(BLOCK_REWARD, remaining_supply(node.chain))), 8)
        txs = []
        if share_list:
            txs.append({"type": "shares", "list": share_list})
        if reward > 0:
            if counts:
                txs += [make_reward(a, amt)
                        for a, amt in sorted(split_amounts(reward, counts).items())]
            else:
                txs.append(make_reward(node.payout_address, reward))
        return Block(prev.index + 1, txs, prev_hash)

    with node.lock:
        node._ensure_share_height()
        prev = node.chain.last_block
        prev_hash = prev.compute_hash()
        target = next_target(node.chain.chain)
        s_target = share_target_for(target)
        version = node.cur_shares["version"]
        candidate = build_candidate()

    my_addr = node.payout_address
    ns = int(time.time() * 1e6) & ((1 << 48) - 1)
    nb = 0
    fresh_shares = []
    race_start = time.time()
    last_beat = race_start
    hashes_done = 0
    while True:
        now = time.time()
        if now - last_beat > 15:
            queued = sum(len(v) for v in node.cur_shares["by"].values())
            # memory-hard attempts run in the tens per second, not the thousands,
            # so kH/s would just read as zero and look broken
            rate = hashes_done / max(now - race_start, 0.001)
            print(f"   ...still working on block {prev.index + 1} "
                  f"({int(now - race_start)}s, ~{rate:.0f} hashes/s, "
                  f"{queued} work-share(s) queued for this block)")
            last_beat = now

        for _ in range(B_SHARE):
            ns += 1
            if int(share_hash(prev_hash, my_addr, ns), 16) < s_target:
                fresh_shares.append(ns)

        with node.lock:
            if node.chain.last_block.compute_hash() != prev_hash:
                return None
            for n0 in fresh_shares:
                node._add_share(my_addr, n0)
            if node.cur_shares["version"] != version:
                version = node.cur_shares["version"]
                candidate = build_candidate()
                nb = 0
        for n0 in fresh_shares:
            gossip(node, "/share",
                   {"prev_hash": prev_hash, "address": my_addr, "nonce": n0})
        fresh_shares = []

        found = False
        for _ in range(B_BLOCK):
            candidate.nonce = nb
            if int(candidate.pow_hash(), 16) < target:
                found = True
                break
            nb += 1
        hashes_done += B_SHARE + B_BLOCK

        won = None
        with node.lock:
            if not node.mining:
                return None
            if node.chain.last_block.compute_hash() != prev_hash:
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
                nb = 0
        if won:
            return won


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
        threading.Thread(target=push_chain, args=(node,), daemon=True).start()
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
    if node.mining:
        return "already mining -- type 'stop' to stop."
    node.mining = True
    threading.Thread(target=mining_loop, args=(node,), daemon=True).start()
    add_event(node, "mining started")
    return ("mining started in the background (real proof-of-work; CPU works hard).\n"
            "   Difficulty auto-adjusts: ~10s/block, ~100 SOSA/hour NETWORK-WIDE,\n"
            "   every active miner earning a slice of every block by proven work.\n"
            "   Type 'stop' to stop. Transfers never wait for blocks.")


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
    threading.Thread(target=discovery_beacon, args=(node,), daemon=True).start()
    threading.Thread(target=discovery_listener, args=(node,), daemon=True).start()
    print(f"  This node's address: {node.wallet.address()}")
    print(f"  Browser wallet:      http://localhost:{port}   (dashboard, send, mine)")
    print("  Other Sosaiem nodes on this machine/wifi will be found automatically.")
    load_seeds(node)
    node.no_upnp = "--no-upnp" in sys.argv
    node.no_nostr = "--no-nostr" in sys.argv
    threading.Thread(target=open_the_door, args=(node,), daemon=True).start()
    threading.Thread(target=retry_bootstrap, args=(node,), daemon=True).start()
    threading.Thread(target=seed_keeper, args=(node,), daemon=True).start()
    threading.Thread(target=nostr_announce_loop, args=(node,), daemon=True).start()
    threading.Thread(target=nostr_discover_loop, args=(node,), daemon=True).start()
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
