# Sosaiem (SOSA)

Sosaiem is a real, from-scratch **proof-of-work cryptocurrency** written in Python —
its own blockchain, its own consensus, no dependency on another chain. It is
open-source so anyone can read exactly how it works and verify there is nothing
hidden.

Current build: **2.11.3** · consensus protocol **v2** · target block time **60s** ·
block reward **1.66666667 SOSA** · max supply **12,212,010 SOSA**.

## How rewards work (fair, no owner)

Mining reward for each block is **split proportionally among everyone whose work-shares
are in that block** — the more work you did, the bigger your slice. There is **no pool
owner and no custody**: rewards go straight from each block to each miner's own wallet.
A slower miner's shares stay claimable for several blocks, so honest work isn't thrown
away just for arriving a moment late.

## Running it

Requires Python 3. No packages to install — everything uses the standard library.

- **Run a node:** `python sosaiem_node.py 80`
- **Mine:** run the miner app and point it at your wallet address.
- **Wallet:** run the wallet app to hold and send SOSA.

On Windows you can build click-to-run `.exe` files with `build_exe.bat`, and start
things with `start_miner.bat` / `start_wallet.bat`.

Nodes try to make themselves reachable automatically (UPnP via `portmap.py`) and find
each other through decentralized relays (Nostr via `nostrseed.py`), so the network does
not depend on any single server.

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

This is a young, community-run project. The code here is the version currently live on
the network. Treat it as experimental software.
