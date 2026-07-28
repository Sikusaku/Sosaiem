# Sosaiem

Sosaiem is a community proof-of-work cryptocurrency. No company, no pre-mine —
coins only come into existence by mining. The reference node, miner, and wallet
are all in this repository.

**Current version:** 2.15.15 · protocol 4
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

- **2.15.15** — Carries permanent ON-CHAIN transfer settlement (dormant until
  scheduled). Adds the machinery for transfers to settle inside blocks --
  permanent, every node agrees, no revert -- plus a reconciler that marks an
  in-block transfer settled and clears it from the pending pool and the old
  vote-cache. It stays OFF, behaving exactly like 2.15.14, until the coordinated
  activation height `TRANSFERS_ONCHAIN_HEIGHT = 10000` is reached -- so it is
  safe to install now, ahead of that flag day. Every node must be on 2.15.15+
  before block 10000 (the flag day), like the payout activations. Includes the restart-revert
  fix (2.15.13) and incremental catch-up (2.15.14).

- **2.15.14** — Much faster catch-up. A miner that fell behind used to re-download
  the ENTIRE chain (tens of MB) just to catch up a block or two, so pull-only
  miners (behind a home router) trailed the tip constantly. Catch-up now fetches
  only the missing blocks (a few KB) via `/chain?from=N` and extends the local
  chain, falling back to a full download only when far behind, on a reorg, or
  from a peer without support. Networking only -- no consensus change. Biggest
  benefit once the node being pulled from (your seed) is on this version.

- **2.15.13** — Fixes transfers reverting on restart. On reload the node was
  re-requiring a transfer's approvers to still hold a majority of ALL network
  stake, which almost no ordinary sender does, so confirmed transfers were
  silently dropped and payments snapped back to the sender after a restart. A
  transfer is authorized by the sender's signature (it moves only their own
  coins); reload now keeps any previously-confirmed transfer that still verifies
  and that the sender can still afford. No consensus change.

- **2.15.12** — Faster block propagation. A newly found block is now sent to all
  peers at once instead of one at a time, so a slow or dead peer no longer holds
  up delivery to everyone behind it. This tightens the one-or-two-block trailing
  miners could see on a thin network. Networking only — no consensus change, no
  activation height; coexists with 2.15.11 and 2.15.10.

- **2.15.11** — All-time transfer history in the block explorer: look up any SOSA
  address to see its complete send/receive history (not just the latest few), and
  the Transfers view now pages through the entire ledger. Also fixes a mining node
  that could fall behind and stall on its own minority fork: a miner now detects
  when the network hasn't shown it anyone ahead for a few minutes and rejoins the
  real tip on its own, instead of needing a restart. Networking/explorer only — no
  consensus change, no activation height. Transfer history is per-node (a node
  shows transfers it has confirmed while online); mining history remains fully
  on-chain.

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
