# Sosaiem — Fair Work Payout (Path B: continuous, never-reset shares)

*The goal in one line: **any device, any speed — even a Raspberry Pi — always
gets paid, in proportion to the real work it did.** No threshold, no treadmill,
nothing wasted.*

This is a consensus change. It ships on a coordinated flag day, exactly like
v5/v6. The chain, genesis and balances never reset.

---

## 1. The problem, precisely

Today a "share" is proof of one fixed chunk of work, **bound to a specific block
(its tip)**. When the network finds a new block, the tip moves and a miner's
in-progress hashing is abandoned — it starts over against the new tip.

- A **fast PC** finds its share in seconds, before the tip moves. Fine.
- A **slow PC** might need longer than a block interval to find one share. The tip
  keeps moving out from under it, so it restarts forever and **lands nothing** —
  it worked, but got paid zero. The treadmill.

That breaks the core promise. Path B removes the treadmill entirely.

---

## 2. The core idea: measure work, not "did you hit this exact tip"

Stop treating a share as a lottery ticket tied to one block. Instead, **count the
actual work a miner proves over a rolling window, and pay in proportion to it** —
no matter how long any single piece took or how many tips passed while they worked.

Two things make this work and stay fair:

**(a) A share still proves real work, but at an *easy, fixed* difficulty.**
Every miner — Pi or gaming rig — submits proof-of-work shares at an easy target.
The Pi submits few; the rig submits many. Crucially, a share is valid as long as
it's anchored to *any* recent block in the window (not one exact tip), so slow
work isn't thrown away when the tip ticks over.

**(b) The payout weights each miner by how much work they proved, using a
difficulty-weighted count.** If shares are all the same easy difficulty, this is
just "how many shares did you land in the window." A Pi that landed 1 share and a
rig that landed 400 split the reward 1:400 — both paid, exactly proportional to
work. The Pi's 0.00001 SOSA is as real as the rig's share.

The result: **presence of any work guarantees payment; amount of work sets the
size.** That is "fair to the work they did," for any device.

---

## 3. Why this is safe (the determinism that was missing before)

The reason the old share-chain failed was that it was a **separate distributed
ledger** every node had to agree on — and they drifted, so payouts disagreed and
blocks got rejected. Path B avoids that the same way the current live payout
("paylist") does:

> **The reward split is computed entirely from the shares recorded INSIDE the
> block, which every node already agrees on.**

The block finder collects the recent valid shares it has seen and embeds the list
in the block. Every validator:
1. checks each embedded share is a valid PoW share anchored to a recent block, and
2. recomputes the split from that list and checks the block's payout matches.

Same input (the block's own contents) → same output on every node → **no second
ledger, no desync, no fork.** This is the property we fought all day to get, and
Path B keeps it. Path B is *not* a return to the fragile share-chain; it's the
current in-block payout, made continuous and inclusive.

---

## 4. What actually changes vs. today

Today (paylist, live):
- Shares are bound to one tip; a share whose tip is > ~15 blocks old is rejected.
- A slow miner whose share lands late, or who never finishes against a moving tip,
  is left out.

Path B:
- **Easy fixed share target** (a consensus constant, set at the flag day) so even a
  Pi lands shares regularly.
- **Anchor window, not exact tip:** a share counts if anchored to *any* block in
  the last N (wider window), so slow work still lands.
- **Rolling accumulation:** shares accumulate across the window and are credited by
  difficulty-weighted count, so nothing a miner proved is wasted.
- **Fair cap kept:** the "every distinct address gets a slot before volume fills the
  rest" rule (already shipped) guarantees inclusion even when the list is capped.

Everything else — genesis, chain, balances, wallets, block format — stays. The
payout is still `split_amounts(reward, weighted_counts)` embedded in the block.

---

## 5. The one honest tradeoff, and how we handle it

Easier shares mean **more shares flying around** — fast miners produce many, so
blocks carry longer share lists (more bandwidth/storage). We manage this with:

- A **cap** on shares per block (already there: `MAX_SHARES_PER_BLOCK`), plus the
  **fair round-robin** so the cap never crowds out a small miner (already shipped).
- **Difficulty-weighting** so we don't *need* a huge number of shares to represent
  a fast miner — one higher-difficulty share can count as many. (Optional
  refinement; the simple version is just "easy shares, capped fairly.")

We pick the share difficulty so a *very* weak device lands ~1 share per block or
two, and a fast one is represented without flooding. That number is chosen once,
tested, and fixed at the flag day.

---

## 6. Migration — nobody loses anything

1. **Same chain, same balances.** Path B is a new payout *rule*, activated at a
   block height above where we are when the network has updated. History and coins
   are untouched.
2. **Flag day:** below the activation height, blocks validate exactly as today, so
   updated and not-yet-updated nodes agree until the switch. At the height, every
   updated node begins requiring the new fair split. (Same mechanism as v5/v6.)
3. **Rollout order:** ship the app/node with Path B *dormant*, get the network on
   it, test on a throwaway multi-node network (including a deliberately-throttled
   "Pi" node to prove it gets paid), then set and announce the flag-day height.

---

## 7. Build plan (testable stages)

- **Stage B1 — the share rule.** Implement the easy-target, anchor-window share
  validity as a dormant consensus rule (activation height = None). No behavior
  change yet. Verify it validates the existing chain identically.
- **Stage B2 — the weighted split.** Implement difficulty-weighted `split_amounts`
  over the window, computed from the block's embedded shares. Prove byte-identical
  determinism across nodes in tests (the critical safety gate).
- **Stage B3 — the throttled-device test.** On a local multi-node network, run one
  node crippled to Pi-like speed and confirm it lands shares and gets paid every
  few blocks, proportional to its work.
- **Stage B4 — flag day.** Only after B1–B3 pass on real nodes: set the activation
  height, ship, announce.

Each stage is dormant/testable; nothing touches the live chain until B4.

---

## 8. Decisions I need from you

1. **Share difficulty target:** how weak a device must always-get-paid define. "A
   5-year-old laptop lands a share every block" vs "a Raspberry Pi Zero lands one
   every few blocks." The weaker the floor, the easier the target, the more shares
   fly around. Your call sets the constant.
2. **Difficulty-weighting:** simple ("count easy shares, cap fairly") or weighted
   ("one share can represent more work")? Simple is safer to ship first; weighted
   scales better later. I recommend **simple first**.
3. **Rollout patience:** are you okay shipping Path B *dormant* first and doing the
   throttled-device test before the flag day — i.e. not activating it same-day?
   (Strongly recommended — this is the change that must not be rushed.)

---

## 9. Bottom line

Path B makes the promise real: **every device that does any honest work gets paid
for exactly that work, always.** It does so without bringing back the fragile
share-chain — the split stays computed from the block's own contents, so nodes
can't disagree. It's a real consensus change, so it goes through a dormant →
tested → flag-day rollout, and the chain and everyone's coins carry forward
untouched.

This is Sosaiem as you designed it. Let's build it carefully.
