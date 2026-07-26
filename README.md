# Sosaiem

Sosaiem is a community proof-of-work cryptocurrency. No company, no pre-mine —
coins only come into existence by mining. The reference node, miner, and wallet
are all in this repository.

**Current version:** 2.15.10 · protocol 4
**Website / downloads:** https://sosaiem.com

## Network parameters

| | |
|---|---|
| Consensus | Proof of work (scrypt, memory-hard, ~8 MB per attempt) |
| Target block time | 60 seconds |
| Block reward | 1.66666667 SOSA (100 SOSA/hour) |
| Max supply | 12,212,010 SOSA |
| Wallet signatures | ML-DSA-65 (post-quantum) |
| Genesis hash | `c09bb5567bfd98d5afbd073dd1a764a94e4f19a0dceb35d4bef898b0595d21f0` |

## Fair payouts (share-chain)

Mining rewards are not kept by whoever happens to find a block. Sosaiem runs a
decentralized share-chain (P2Pool-style): every miner's proof-of-work is
recorded as shares, and each block reward is split across the recent window
(PPLNS, last 300 shares) in proportion to the work each address actually did.
Shares stay payable for a short window so slower miners aren't cut out on timing
alone, and orphaned shares are still credited.

This split is deterministic and enforced — every node computes the same
canonical payout from the share-chain, and a block whose rewards don't match it
is rejected. A miner cannot pay only themselves.

### Activation heights

Consensus rule changes are gated to a block height so every node switches
together instead of forking:

- **5400** — fair-payout enforcement (forcing rule) turned on.
- **6375** — fair-split turns on: every block is split across *all* miners who did recent work, in proportion, instead of one miner taking the whole block. (The earlier anchor-recency rule is off in this build.)
- ~~6200 — anchor-recency~~ (superseded): a share only counts toward a payout
  if it was mined against a recent block (within the last 30). This stops a
  dormant branch of old shares from capturing the payout window and starving the
  miners actually working. Below this height the payout is computed exactly as
  before, so nodes on older builds stay in consensus until the whole network has
  updated.

> **Note for miners:** be on 2.15.8 before block 6200. Nodes still on older code
> past that height will disagree on payouts and can fork off onto a minority
> chain.

## Files

| File | Purpose |
|---|---|
| `sosaiem_node.py` | Full node: blockchain, share-chain, P2P, mining loop, HTTP API |
| `sosaiem_miner.py` | Miner (desktop UI) |
| `sosaiem_wallet.py` | Wallet (desktop UI) |
| `blockchain.py` | Block, chain, proof-of-work, difficulty retargeting |
| `coin.py` | Balances, supply, reward schedule |
| `wallet.py` | Post-quantum keys, signing, verification, addresses |
| `seedphrase.py` | Deterministic key derivation from a seed phrase |
| `nostrseed.py` | Peer discovery helper |
| `portmap.py` | UPnP/NAT port mapping helper |
| `seeds.txt` | Bootstrap seed nodes |
| `build_exe.bat` | Build Windows `.exe`s (miner + wallet) |
| `start_miner.bat` / `start_wallet.bat` | Launch helpers |

## Running from source (Mac / Linux / developers)

Requires Python 3.11+ and:

```
pip install dilithium-py cryptography
```

Then:

```
python sosaiem_node.py      # run a node
python sosaiem_miner.py     # mine
python sosaiem_wallet.py    # wallet
```

Windows users can download prebuilt apps from https://sosaiem.com, or run
`build_exe.bat` to package the `.exe`s themselves.

## Changelog

- **2.15.10** — Pay-the-block's-shares: every block reward is split across the
  proof-of-work shares recorded IN that block, which every node verifies and
  reads identically. This makes an updated miner's blocks pay *everyone* who did
  work in them (fixing "several miners worked, one got paid") with no dependence
  on share propagation. Activates at block **6500**. Includes the startup-hang fix.

- **2.15.9** — Fair split: every block reward is split across all miners who did
  recent work, in proportion, instead of one miner taking the whole block.
  Activates at block **6375**. Also fixes a startup hang (share-cache was being
  re-verified on every boot) and a broken share-exchange endpoint between nodes.
- **2.15.8** — Anchor-recency payout groundwork.
- **2.15.6** — Prior release.
