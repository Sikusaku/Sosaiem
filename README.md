# Sosaiem (SOSA)

A small, community-run, ASIC-resistant proof-of-work coin with post-quantum
(ML-DSA / Dilithium) wallet signatures and feeless transfers. Mining creates SOSA;
stake-voting/on-chain settlement moves it. One ledger, open to everyone.

- Website / downloads: https://sosaiem.com
- Target block time: 60s · Reward: 1.66666667 SOSA · Max supply: 12,212,010

## Run a node / mine

### Easiest — the Sosaiem app (recommended)

1. Download **`Sosaiem.exe`** from https://sosaiem.com and run it.
2. On first launch it asks you to **create a new wallet** (shows your 17-word
   recovery phrase — write it down) or **import** an existing phrase.
3. It syncs to the network, then you can mine, send, and browse the chain from
   one window (Mine / Send / Explorer / Node). Running it makes you a full node.

To build the exe yourself: unzip the source, run `build_app_exe.bat` →
`dist\Sosaiem.exe`. Or run from source: `python sosaiem_app.py`.

### From source (node only)

1. Download the source and unzip it.
2. Run a node:  `python sosaiem_node.py 7000`
3. Once synced, type `mine` (or use the app's mine button).
4. To make the classic Windows executables, run `build_exe.bat`.

Requires Python 3. Dependencies are standard-library plus the bundled modules
(`dilithium-py` and `cryptography` install automatically on first run).

## Upcoming — fair-work payout (flag day at block 15555)

Sosaiem is upgrading so that **any device — even a Raspberry Pi — always gets
paid for exactly the work it does.** At block **15555** every updated node
switches to a difficulty-weighted, in-block payout with far easier work-shares,
so no miner is ever left out for being slow.

**This is a scheduled hard fork.** Every node must be on this release before
block 15555. Below that height the chain behaves exactly as v2.17.0, so updated
and not-yet-updated nodes agree until the switch. After it, non-updated nodes
will be on a minority chain and must update to rejoin (coins are safe — same
history to the fork point). See `SOSAIEM-FAIR-PAYOUT-DESIGN.md` for the full
design.

## Current release — v2.17.0

This release ships the **v6 consensus rules**, which **activated at height 11750**
and are now live. Below that height the node behaved exactly like v2.16.0; from
11750 onward these are in force on every updated node:

- **Work-based fork choice** — the heaviest (most cumulative proof-of-work) chain
  wins, not merely the longest. LWMA makes per-block work vary, so "longest" could
  pick a longer low-work fork over a shorter honest one; this closes that.
- **Median-time-past timestamps** — a block's timestamp must exceed the median of
  the previous 11 blocks, so a miner can't feed LWMA backwards times to skew
  difficulty. Fully deterministic (no wall clock), so no node's clock can disagree.

Also in this release (always on, no flag day needed):
- **Push-delivery fix** — `push_chain` no longer treats a peer's "resync"/"duplicate"
  reply as successful delivery, so a home miner stuck on a fork actually receives
  the chain instead of silently staying behind.
- **Verified-cache eviction** — the proof cache drops its oldest entries at the cap
  instead of wiping everything, so a chain longer than the cap no longer triggers a
  full re-verification storm.
- **Push/pull agreement** — `handle_submit_chain` and `is_better` now agree on
  equal-length chains, so a pushed equal-height reorg no longer silently fails.

### Activation / flag day

`sosaiem_node.py` sets `CONSENSUS_V6_HEIGHT`. This exact value must be identical on
**every** node and in every build (the zip, both .exes, the seed node, every miner).
Nodes on a different value fork at that height. `999_999_999` means the v6 rules are
off. Everyone must be on v2.17.0 before block 11750.

## Previous release — v2.16.0

This release ships the **v5 consensus rules**, which are **dormant** until a
coordinated activation height (`LWMA_HEIGHT` in `blockchain.py`). Below that height
the node behaves exactly like v4, so updated and not-yet-updated nodes agree until
the flag day. At the activation height, for every updated node, these switch on
together:

- **LWMA difficulty** — retargets every block on a linearly-weighted window, so
  difficulty tracks hashrate tightly and a miner can't run ahead onto a private
  fork. This is the fix for the difficulty-driven forking / desync.
- **On-chain transfer settlement** — transfers settle in blocks instead of the
  older vote cache, so they land reliably and permanently.

Also in this release (always on, no flag day needed):
- **Sync-filter fix** — a node re-checks peers even when slightly ahead, so it can
  climb back off a fork.
- Earlier fixes: fair share-chain payout (PPLNS), restart-revert fix, fast
  incremental sync, and a request-handling hardening (global socket timeout +
  larger worker pool) so the node stays responsive under flaky peers.

### Activation / flag day

`blockchain.py` sets `LWMA_HEIGHT`. This exact value must be identical on **every**
node and in every build (the zip, both .exes, the seed node, every miner). Nodes on
a different value fork at that height. `999_999_999` means the v5 rules are off.

## Files

- `sosaiem_node.py` — the node (server, sync, mining, consensus)
- `blockchain.py` — blocks, chain validation, difficulty (LWMA)
- `coin.py` — balances, rewards, transfers
- `wallet.py` — ML-DSA (Dilithium) keys and signing
- `seedphrase.py` — recovery-phrase wallet backup
- `portmap.py`, `nostrseed.py` — peer reachability / discovery helpers
- `sosaiem_miner.py`, `sosaiem_wallet.py` — the miner and wallet apps
- `build_exe.bat`, `start_miner.bat`, `start_wallet.bat` — Windows helpers
- `seeds.txt` — starter list of nodes to connect to

## License

Community project — owned by no one, open to everyone.
