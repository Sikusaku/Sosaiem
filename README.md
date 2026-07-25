# Sosaiem (SOSA)

Sosaiem is a real, from-scratch **proof-of-work cryptocurrency** written in Python —
its own blockchain, its own consensus, no dependency on another chain. It is
open-source so anyone can read exactly how it works and verify there is nothing
hidden.

Current build: **2.15.1** · consensus protocol **v4** · target block time **60s** ·
block reward **1.66666667 SOSA** · max supply **12,212,010 SOSA**.

## What makes it different

- **ASIC-resistant mining.** Proof-of-work is memory-hard (scrypt, 8 MB per attempt),
  so it stays mineable on a normal PC instead of turning into a specialised-hardware
  race.
- **No pool operator.** Miners submit verifiable work-shares and each block's reward is
  split proportionally across everyone's shares; every node re-checks the maths. You get
  a fair cut of the work you did, with no operator taking a slice.
- **Feeless, offline-capable transfers.** To send, your own device does a few seconds of
  proof-of-work on the payment (no fee), and the chain settles it into a block. A
  transfer completes even if the recipient — or everyone else — is offline, and it
  settles in a block or two (about a minute). Dependable rather than instant.
- **Post-quantum from genesis.** Signatures use ML-DSA (NIST FIPS 204), so the network
  is secure against quantum computers from its first block.
- **No premine, no founder cut, no KYC.** Every coin is mined in the open.

## Running it

Requires Python 3. Standard library only — nothing to install.

- **Run a node:** `python sosaiem_node.py 80`
- **Mine / wallet:** run the miner and wallet apps (one-click `.exe` on Windows via
  `build_exe.bat`, or run the Python directly on Mac/Linux).

Nodes make themselves reachable automatically where possible (UPnP via `portmap.py`) and
find each other through decentralized relays (Nostr via `nostrseed.py`), so the network
does not depend on any single server.

## Files

| File | What it is |
| --- | --- |
| `sosaiem_node.py` | The node: mining, transfers, P2P networking, all the rules |
| `blockchain.py` | Blocks, chain, difficulty |
| `coin.py` | Rewards, transfers, balances, supply cap |
| `wallet.py`, `seedphrase.py` | Keys, signing, recovery phrases |
| `sosaiem_miner.py`, `sosaiem_wallet.py` | The miner and wallet apps |
| `portmap.py` | Asks the router to open a port (UPnP) so home nodes are reachable |
| `nostrseed.py` | Finds the network via Nostr relays, no central server needed |
| `seeds.txt` | Starter list of nodes to connect to |
| `build_exe.bat`, `start_miner.bat`, `start_wallet.bat` | Windows build/run helpers |

## Note

This is a young, community-run project — experimental software. Transfers settle inside
blocks, which relies on mining continuing; securing them beyond the mining era (~14
years out) is an open question the project intends to address before then.
