"""Sosaiem Miner -- paste a payout address, press Start. It never holds your keys."""

import os
import sys
import threading
import time

try:
    import tkinter as tk
except Exception:
    tk = None

import sosaiem_node as core

PLATE = "#0b1712"
PANEL = "#122420"
GILT = "#c6a24a"
GILT2 = "#e3c982"
PAPER = "#e8ede4"
DIM = "#9db0a2"
SAGE = "#7f9c8a"
RED = "#c96a5f"
MONO = ("Consolas", 10)
PAYOUT_FILE = "miner_payout.txt"


def start_node(port):
    node = core.Node(port)
    core.start_server(node)
    threading.Thread(target=core.auto_sync_loop, args=(node,), daemon=True).start()
    threading.Thread(target=core.discovery_beacon, args=(node,), daemon=True).start()
    threading.Thread(target=core.discovery_listener, args=(node,), daemon=True).start()
    core.load_seeds(node)
    return node


def valid_address(a):
    return isinstance(a, str) and a.startswith("SOSA") and len(a) == 44


def load_payout():
    try:
        if os.path.exists(PAYOUT_FILE):
            return open(PAYOUT_FILE).read().strip()
    except Exception:
        pass
    return ""


def save_payout(addr):
    try:
        open(PAYOUT_FILE, "w").write(addr)
    except Exception:
        pass


class MinerApp:
    def __init__(self, root, node):
        self.root = root
        self.node = node
        root.title("Sosaiem Miner")
        root.configure(bg=PLATE)
        root.geometry("560x600")
        root.minsize(500, 540)

        tk.Label(root, text="SOSAIEM \u25c6 MINER", bg=PLATE, fg=GILT,
                 font=("Georgia", 15, "bold")).pack(pady=(16, 2))
        tk.Label(root, text="strikes coins to any address \u00b7 holds no keys",
                 bg=PLATE, fg=SAGE, font=("Georgia", 9, "italic")).pack()

        box = tk.Frame(root, bg=PLATE)
        box.pack(fill="x", padx=22, pady=(18, 0))
        tk.Label(box, text="PAYOUT ADDRESS  (copy it from your Wallet app)",
                 bg=PLATE, fg=SAGE, font=("Consolas", 8)).pack(anchor="w")
        self.addr_entry = tk.Entry(box, bg=PANEL, fg=GILT2, insertbackground=GILT2,
                                   relief="flat", font=MONO, justify="center")
        self.addr_entry.pack(fill="x", ipady=7)
        saved = load_payout()
        if saved:
            self.addr_entry.insert(0, saved)

        self.btn = tk.Button(root, text="START MINING", command=self.toggle,
                             bg=GILT, fg=PLATE, activebackground=GILT2,
                             relief="flat", font=("Consolas", 13, "bold"),
                             padx=30, pady=10)
        self.btn.pack(pady=18)
        self.state_lbl = tk.Label(root, text="idle", bg=PLATE, fg=DIM,
                                  font=("Georgia", 10, "italic"))
        self.state_lbl.pack()

        stats = tk.Frame(root, bg=PANEL)
        stats.pack(fill="x", padx=22, pady=14, ipady=8)
        self.earned = self._stat(stats, "session earned", "0.000000 SOSA")
        self.rate = self._stat(stats, "rate", "\u2014")
        self.height = self._stat(stats, "chain height", "\u2014")
        self.peers = self._stat(stats, "peers", "\u2014")

        tk.Label(root, text="ACTIVITY", bg=PLATE, fg=SAGE,
                 font=("Consolas", 8)).pack(anchor="w", padx=22)
        self.feed = tk.Text(root, bg=PANEL, fg=DIM, font=("Consolas", 9),
                            relief="flat", height=9, state="disabled", wrap="word")
        self.feed.pack(fill="both", expand=True, padx=22, pady=(2, 8))

        tk.Label(root, text="Real proof-of-work: your CPU works hard while mining. "
                            "Every active miner earns a slice of every block.",
                 bg=PLATE, fg=DIM, font=("Georgia", 9, "italic"),
                 wraplength=480).pack(pady=(0, 12))

        root.protocol("WM_DELETE_WINDOW", self.close)
        self.refresh()

    def _stat(self, parent, label, value):
        cell = tk.Frame(parent, bg=PANEL)
        cell.pack(side="left", expand=True, fill="x")
        tk.Label(cell, text=label.upper(), bg=PANEL, fg=SAGE,
                 font=("Consolas", 7)).pack()
        val = tk.Label(cell, text=value, bg=PANEL, fg=PAPER, font=("Consolas", 11))
        val.pack()
        return val

    def toggle(self):
        if self.node.mining:
            core.stop_mining(self.node)
            self.btn.config(text="START MINING", bg=GILT)
            self.addr_entry.config(state="normal")
            self.state_lbl.config(text="stopping\u2026", fg=DIM)
            return
        addr = self.addr_entry.get().strip()
        if not valid_address(addr):
            self.state_lbl.config(text="that isn't a SOSA address \u2014 copy it "
                                       "from your Wallet app", fg=RED)
            return
        self.node.payout_address = addr
        save_payout(addr)
        self.addr_entry.config(state="disabled")
        core.start_mining(self.node)
        self.btn.config(text="STOP MINING", bg=RED)
        self.state_lbl.config(text="mining \u2014 rewards go to your wallet", fg=GILT2)

    def refresh(self):
        n = self.node
        st = n.mine_stats
        elapsed = (time.time() - st["start"]) if (n.mining and st["start"]) else 0
        rate = (st["earned"] / elapsed * 3600) if elapsed > 1 else 0
        with n.lock:
            height = len(n.chain.chain)
            peers = len(n.peers)
            events = list(n.events)
        self.earned.config(text=f"{st['earned']:.6f} SOSA")
        self.rate.config(text=(f"~{rate:.1f}/hr" if n.mining else "\u2014"))
        self.height.config(text=str(height))
        self.peers.config(text=str(peers))
        if not n.mining and self.btn.cget("text") == "STOP MINING":
            self.btn.config(text="START MINING", bg=GILT)
            self.addr_entry.config(state="normal")
        if n.mining:
            self.state_lbl.config(text="mining \u2014 rewards go to your wallet",
                                  fg=GILT2)
        self.feed.config(state="normal")
        self.feed.delete("1.0", "end")
        self.feed.insert("1.0", "\n".join(events) if events else
                         "connect a wallet address and press start\u2026")
        self.feed.config(state="disabled")
        self.root.after(1500, self.refresh)

    def close(self):
        self.node.mining = False
        try:
            if getattr(self.node, "server", None):
                self.node.server.shutdown()
                self.node.server.server_close()
        except Exception:
            pass
        self.root.destroy()
        import os
        os._exit(0)


def main():
    if tk is None:
        print("tkinter is missing. Install Python from python.org (it includes it).")
        return
    port = 7001
    for arg in sys.argv[1:]:
        if arg.isdigit():
            port = int(arg)
    node = start_node(port)
    root = tk.Tk()
    MinerApp(root, node)
    root.mainloop()


if __name__ == "__main__":
    main()
