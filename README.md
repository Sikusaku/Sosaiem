# Sosaiem — society's coin

A post-quantum, feeless, leaderless cryptocurrency, built in the open and owned by no one.
No company, no pre-mine, no gatekeepers. Website: **[sosaiem.com](https://sosaiem.com)** · Chat: **[Discord](https://discord.gg/GQSrcpXcpy)**

Every line here is readable — that's the point. Inspect it before you trust it.

## What it is

- **Post-quantum from genesis.** Every wallet and vote is signed with ML-DSA (NIST FIPS 204),
  designed to resist quantum computers — not retrofitted later.
- **Fixed supply: 12,212,010 SOSA.** Created only by mining, ~100 SOSA/hour network-wide, until the
  cap is reached. No lever to print more.
- **Fair mining, built for ordinary machines.** The work is memory-hard (8 MB per attempt), which
  strips purpose-built mining chips of the advantage they get from plain hashing. Every active miner
  also earns a share of every block by verifiable work — pool-smooth earnings, no pool operator.
- **17-word recovery phrases.** Lose the computer, write the words in, get the wallet back.
- **Feeless transfers.** Sending costs nothing and waits for no miner: transfers confirm in seconds
  by stake-weighted vote among holders. Your coins are your voice; forged identities carry no weight.
- **Every node is the whole coin.** Wallet, explorer, and miner run on each participant's own machine.

Read the full design in the [whitepaper](https://sosaiem.com/whitepaper.html).

## Run it

**Easiest (Windows):** download the ready-made apps from
[sosaiem.com](https://sosaiem.com) — `Sosaiem-Wallet` and `Sosaiem-Miner`. No install.

**From source (any OS):**

```
pip install dilithium-py cryptography
python3 sosaiem_wallet.py      # your wallet — hold and send SOSA
python3 sosaiem_miner.py       # paste your wallet address, then mine
```

A node finds the network automatically. To point at specific nodes, list them in `seeds.txt`
(one URL per line).

## Files

| File | What it is |
|------|-----------|
| `sosaiem_node.py` | the full node — mining, stake-voting transfers, P2P networking, block explorer |
| `sosaiem_wallet.py` | desktop wallet app (holds your key) |
| `sosaiem_miner.py` | desktop miner app (never holds keys; mines to any address) |
| `blockchain.py` | blocks, chain, proof-of-work, difficulty |
| `coin.py` | transfers, rewards, balances, supply cap |
| `wallet.py` | post-quantum keys, signing, addresses |
| `seedphrase.py` | 17-word wallet recovery |
| `portmap.py` | asks the router to open a port, so home machines can host newcomers |
| `nostrseed.py` | announces the node to public relays, so finding the network needs no central list |
| `build_exe.bat` | builds the Windows apps from source |

## Honest status

Sosaiem is a young, community-run experiment. It works, but it has real limits, stated plainly
rather than hidden:

- **51% / majority-stake:** while few people mine, the chain can be out-mined and rewritten. Security
  grows only as more independent people run miners and nodes.
- **Reachability:** the network currently leans on reachable nodes as a backbone (as Bitcoin does);
  fully serverless peer-to-peer through home routers is not solved here.
- **Not audited:** the cryptographic libraries are standard, but this protocol code has had no formal
  security review.
- **Nobody can promise it will be worth anything.** Mine it because the idea is interesting.

Run a node because the idea matters to you. Read the code. Decide for yourself.

## Building the Windows apps

```
pip install cryptography dilithium-py pyinstaller
build_exe.bat
```

Produces `dist/Sosaiem-Wallet.exe` and `dist/Sosaiem-Miner.exe`. They are unsigned, so antivirus
software will complain; that is unavoidable without a code-signing certificate.
