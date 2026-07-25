"""Transfers, mining rewards, balances, and the fixed supply cap."""

import time
import json
import hashlib

from wallet import Wallet, verify_signature
from blockchain import Blockchain, Block, TARGET_BLOCK_SECONDS


HOURLY_RATE = 100


BLOCK_REWARD = round(HOURLY_RATE * TARGET_BLOCK_SECONDS / 3600.0, 8)
MAX_SUPPLY = 12_212_010


def _canonical(tx: dict) -> str:
    # The signature and the send-time work stamp are BOTH excluded from what
    # gets signed. The signature obviously can't sign itself; the work stamp
    # (work_nonce) is added after signing and is bound to the signature by its
    # own hash, so it must not change the signed content -- otherwise stamping a
    # transfer would break its signature. Old transfers never had a work_nonce,
    # so excluding it leaves every existing signature valid.
    core = {k: tx[k] for k in tx if k not in ("signature", "work_nonce")}
    return json.dumps(core, sort_keys=True)


def amount_is_sane(amt, allow_zero: bool = False) -> bool:
    """
    The one place an amount is judged. An amount must be a real, finite,
    non-negative number inside the supply cap.

    JSON can carry NaN and Infinity, and NaN compares False against everything.
    One NaN in the ledger therefore slips past the supply cap, the reward check
    and the balance check alike, and poisons the arithmetic for good. Booleans
    are excluded too: True == 1 in Python, and a flag is not money.
    """
    if isinstance(amt, bool) or not isinstance(amt, (int, float)):
        return False
    if amt != amt or amt in (float("inf"), float("-inf")):   # NaN / +-Inf
        return False
    if amt < 0 or (amt == 0 and not allow_zero):
        return False
    return amt <= MAX_SUPPLY


def _address_from_pubkey(pubkey_hex: str) -> str:
    digest = hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()
    return "SOSA" + digest[:40]


def make_transfer(sender: Wallet, recipient_address: str, amount: float) -> dict:
    tx = {
        "type": "transfer",
        "from": sender.address(),
        "from_pubkey": sender.public_key_hex(),
        "to": recipient_address,
        "amount": amount,
        "timestamp": time.time(),
    }
    tx["signature"] = sender.sign(_canonical(tx))
    return tx


def make_reward(recipient_address: str, amount: float) -> dict:
    return {
        "type": "reward",
        "from": "SOSAIEM_NETWORK",
        "to": recipient_address,
        "amount": amount,
        "timestamp": time.time(),
    }


def transfer_is_valid(tx: dict) -> bool:
    if not isinstance(tx, dict):
        return False
    if tx.get("type") == "reward":
        return amount_is_sane(tx.get("amount"), allow_zero=True)
    if tx.get("type") != "transfer":
        return False
    # every field must be present and the right shape -- a missing key used to
    # raise KeyError straight out of the request handler
    frm, pub = tx.get("from"), tx.get("from_pubkey")
    to, sig = tx.get("to"), tx.get("signature")
    if not all(isinstance(v, str) for v in (frm, pub, to, sig)):
        return False
    if not frm.startswith("SOSA") or not to.startswith("SOSA"):
        return False
    if not amount_is_sane(tx.get("amount")):
        return False
    try:
        if frm != _address_from_pubkey(pub):
            return False
        return verify_signature(pub, _canonical(tx), sig)
    except Exception:
        return False


def compute_balances(chain: Blockchain) -> dict:
    balances = {}
    for block in chain.chain:
        for tx in block.transactions:
            if not isinstance(tx, dict):
                continue
            kind = tx.get("type")
            if kind == "transfer":
                balances[tx["from"]] = balances.get(tx["from"], 0) - tx["amount"]
                balances[tx["to"]] = balances.get(tx["to"], 0) + tx["amount"]
            elif kind == "reward":
                balances[tx["to"]] = balances.get(tx["to"], 0) + tx["amount"]
    return balances


def total_minted(chain: Blockchain) -> float:
    total = 0.0
    for block in chain.chain:
        for tx in block.transactions:
            if isinstance(tx, dict) and tx.get("type") == "reward":
                total += tx["amount"]
    return round(total, 8)


def remaining_supply(chain: Blockchain) -> float:
    return round(MAX_SUPPLY - total_minted(chain), 8)


def print_balances(chain: Blockchain, label_map=None):
    balances = compute_balances(chain)
    print("\n  ----- SOSA balances -----")
    for addr, bal in balances.items():
        name = (label_map or {}).get(addr, "")
        print(f"     {addr[:16]}...  {bal:>14.4f} SOSA   {name}")
    print(f"     {'TOTAL IN CIRCULATION':<19}  {sum(balances.values()):>14.4f} SOSA")
    print(f"     minted so far: {total_minted(chain):.4f} / {MAX_SUPPLY} "
          f"(remaining: {remaining_supply(chain):.4f})")
    print()


def mine_round(chain: Blockchain, miner_powers: dict, pending_transfers=None,
               verbose=True):
    if pending_transfers is None:
        pending_transfers = []

    left = remaining_supply(chain)
    reward = round(max(0.0, min(BLOCK_REWARD, left)), 8)

    balances = compute_balances(chain)
    valid_transfers = []
    for tx in pending_transfers:
        ok = transfer_is_valid(tx)
        affordable = tx.get("amount", 0) > 0 and balances.get(tx["from"], 0) >= tx["amount"]
        if ok and affordable:
            valid_transfers.append(tx)
            balances[tx["from"]] -= tx["amount"]
            balances[tx["to"]] = balances.get(tx["to"], 0) + tx["amount"]
        else:
            reason = "bad signature" if not ok else "insufficient balance"
            if verbose:
                print(f"   x rejected transfer from {tx.get('from','?')[:16]}... ({reason})")

    total_power = sum(miner_powers.values()) or 1
    rewards = []
    if reward > 0:
        for addr, power in miner_powers.items():
            amount = round(reward * power / total_power, 8)
            if amount > 0:
                rewards.append(make_reward(addr, amount))

    all_txs = rewards + valid_transfers
    new_block = Block(
        index=chain.last_block.index + 1,
        transactions=all_txs,
        previous_hash=chain.last_block.compute_hash(),
    )
    block_hash = chain._mine_block(new_block)
    chain.chain.append(new_block)

    if verbose:
        if reward > 0:
            print(f"   Block {new_block.index} mined (hash {block_hash[:14]}...), "
                  f"minted {reward:.6f} SOSA, split by power:")
            for addr, power in miner_powers.items():
                pct = 100 * power / total_power
                earned = round(reward * power / total_power, 6)
                print(f"     {addr[:16]}...  power={power}  "
                      f"({pct:5.1f}%)  ->  {earned:.6f} SOSA")
        else:
            print(f"   Block {new_block.index} mined (hash {block_hash[:14]}...) -- "
                  f"cap reached, no new SOSA minted (chain still secured).")
    return rewards


if __name__ == "__main__":
    print("=" * 66)
    print(" SOSAIEM -- per-block mining (coins exist only when mined)")
    print("=" * 66)
    print(f" Block reward: {BLOCK_REWARD} SOSA  (aims for ~{HOURLY_RATE}/hour at "
          f"{TARGET_BLOCK_SECONDS}s/block)\n")

    chain = Blockchain()
    alice, bob, carol = Wallet(), Wallet(), Wallet()
    names = {alice.address(): "Alice (power 3)",
             bob.address():   "Bob   (power 2)",
             carol.address(): "Carol (power 1)"}
    powers = {alice.address(): 3, bob.address(): 2, carol.address(): 1}

    print("Mining 5 blocks. Each mints a FIXED reward, split by work done:\n")
    for _ in range(5):
        mine_round(chain, powers)
    print_balances(chain, names)
    print("Every block minted the same fixed amount -- coins appeared ONLY because")
    print("blocks were mined. No mining would have meant no new coins, nothing lost.\n")

    print("-" * 66)
    print("CAP DEMO (pretend the cap is only 1.0 SOSA so we can reach it):")
    real_cap = MAX_SUPPLY
    MAX_SUPPLY = round(total_minted(chain) + 0.30, 8)
    print(f"   pretend cap set so only 0.30 SOSA remains to be minted...")
    for _ in range(5):
        mine_round(chain, powers, verbose=True)
    print(f"   minted now: {total_minted(chain):.6f}  (pretend cap {MAX_SUPPLY})")
    MAX_SUPPLY = real_cap
    print(f"   real cap restored to {MAX_SUPPLY}.")
    print("   Notice the last blocks minted 0 -- the cap is a hard ceiling.\n")

    print("Chain still valid? ->", chain.is_chain_valid())
