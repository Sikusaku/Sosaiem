"""Sosaiem Wallet -- create your address, hold SOSA, send it. Native window, no browser."""

import sys
import threading
import webbrowser

try:
    import tkinter as tk
except Exception:
    tk = None

import sosaiem_node as core

PLATE = "#0b1712"
PANEL = "#122420"
EDGE = "#22362d"
GILT = "#c6a24a"
GILT2 = "#e3c982"
PAPER = "#e8ede4"
DIM = "#9db0a2"
SAGE = "#7f9c8a"
RED = "#c96a5f"
MONO = ("Consolas", 10)
SERIF = ("Georgia", 11)


def start_node(port):
    node = core.Node(port)
    core.start_server(node)
    threading.Thread(target=core.auto_sync_loop, args=(node,), daemon=True).start()
    threading.Thread(target=core.discovery_beacon, args=(node,), daemon=True).start()
    threading.Thread(target=core.discovery_listener, args=(node,), daemon=True).start()
    core.load_seeds(node)
    return node


class WalletApp:
    def __init__(self, root, node):
        self.root = root
        self.node = node
        root.title("Sosaiem Wallet")
        root.configure(bg=PLATE)
        root.geometry("560x680")
        root.minsize(500, 600)

        tk.Label(root, text="SOSAIEM \u25c6 WALLET", bg=PLATE, fg=GILT,
                 font=("Georgia", 15, "bold")).pack(pady=(16, 2))
        tk.Label(root, text="society's coin \u00b7 post-quantum \u00b7 feeless",
                 bg=PLATE, fg=SAGE, font=("Georgia", 9, "italic")).pack()

        addr_box = tk.Frame(root, bg=PLATE)
        addr_box.pack(fill="x", padx=22, pady=(16, 0))
        tk.Label(addr_box, text="MY ADDRESS", bg=PLATE, fg=SAGE,
                 font=("Consolas", 8)).pack(anchor="w")
        row = tk.Frame(addr_box, bg=PLATE)
        row.pack(fill="x")
        self.addr_var = tk.StringVar(value=node.wallet.address())
        addr_entry = tk.Entry(row, textvariable=self.addr_var, state="readonly",
                              readonlybackground=PANEL, fg=GILT2, font=MONO,
                              relief="flat", justify="center")
        addr_entry.pack(side="left", fill="x", expand=True, ipady=6)
        tk.Button(row, text="Copy", command=self.copy_addr, bg=GILT, fg=PLATE,
                  activebackground=GILT2, relief="flat", font=("Consolas", 9, "bold"),
                  padx=12).pack(side="left", padx=(8, 0))

        self.balance = tk.Label(root, text="0.000000 SOSA", bg=PLATE, fg=PAPER,
                                font=("Georgia", 26, "bold"))
        self.balance.pack(pady=(18, 0))
        self.available = tk.Label(root, text="", bg=PLATE, fg=DIM, font=SERIF)
        self.available.pack()

        send = tk.LabelFrame(root, text=" Send SOSA (feeless) ", bg=PANEL, fg=SAGE,
                             font=("Consolas", 9), bd=1, relief="solid",
                             labelanchor="n")
        send.pack(fill="x", padx=22, pady=16, ipady=6)
        tk.Label(send, text="To address", bg=PANEL, fg=DIM,
                 font=("Consolas", 8)).pack(anchor="w", padx=12, pady=(6, 0))
        self.to_entry = tk.Entry(send, bg=PLATE, fg=PAPER, insertbackground=GILT2,
                                 relief="flat", font=MONO)
        self.to_entry.pack(fill="x", padx=12, ipady=5)
        tk.Label(send, text="Amount", bg=PANEL, fg=DIM,
                 font=("Consolas", 8)).pack(anchor="w", padx=12, pady=(8, 0))
        amt_row = tk.Frame(send, bg=PANEL)
        amt_row.pack(fill="x", padx=12)
        self.amt_entry = tk.Entry(amt_row, bg=PLATE, fg=PAPER, insertbackground=GILT2,
                                  relief="flat", font=MONO, width=18)
        self.amt_entry.pack(side="left", ipady=5)
        tk.Button(amt_row, text="Send", command=self.send, bg=GILT, fg=PLATE,
                  activebackground=GILT2, relief="flat",
                  font=("Consolas", 10, "bold"), padx=20).pack(side="left", padx=10)
        self.send_msg = tk.Label(send, text="", bg=PANEL, fg=DIM, font=("Georgia", 9),
                                 wraplength=460, justify="left")
        self.send_msg.pack(anchor="w", padx=12, pady=(6, 2))

        tk.Label(root, text="ACTIVITY", bg=PLATE, fg=SAGE,
                 font=("Consolas", 8)).pack(anchor="w", padx=22)
        self.feed = tk.Text(root, bg=PANEL, fg=DIM, font=("Consolas", 9),
                            relief="flat", height=10, state="disabled", wrap="word")
        self.feed.pack(fill="both", expand=True, padx=22, pady=(2, 8))

        self.status = tk.Label(root, text="starting\u2026", bg=PLATE, fg=SAGE,
                               font=("Consolas", 8), anchor="w")
        self.status.pack(fill="x", padx=22)
        tk.Label(root, text=f"Back up {node.wallet_file} \u2014 that file IS your coins.",
                 bg=PLATE, fg=RED, font=("Georgia", 9, "italic")).pack(pady=(4, 12))

        root.protocol("WM_DELETE_WINDOW", self.close)
        self.refresh()

    def copy_addr(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.node.wallet.address())
        self.send_msg.config(text="address copied", fg=SAGE)

    def send(self):
        to = self.to_entry.get().strip()
        try:
            amt = float(self.amt_entry.get().strip())
        except ValueError:
            self.send_msg.config(text="amount must be a number.", fg=RED)
            return
        ok, msg = core.do_send(self.node, to, amt)
        self.send_msg.config(text=msg, fg=(GILT2 if ok else RED))
        if ok:
            self.to_entry.delete(0, "end")
            self.amt_entry.delete(0, "end")

    def refresh(self):
        n = self.node
        with n.lock:
            balances = n.get_balances()
            me = n.wallet.address()
            bal = balances.get(me, 0)
            pend = [(s, t) for s, t in n.transfers.items() if s not in n.confirmed]
            pend_out = sum(t.get("amount", 0) for _, t in pend if t.get("from") == me)
            blocks = len(n.chain.chain)
            minted = core.total_minted(n.chain)
            validators = len(n.registry)
            peers = len(n.peers)
            events = list(n.events)
        self.balance.config(text=f"{bal:.6f} SOSA")
        if pend_out > 0:
            self.available.config(text=f"available {bal - pend_out:.6f} \u00b7 "
                                       f"{pend_out:.6f} awaiting votes")
        else:
            self.available.config(text="your balance is also your voting weight")
        self.feed.config(state="normal")
        self.feed.delete("1.0", "end")
        self.feed.insert("1.0", "\n".join(events) if events else "waiting for activity\u2026")
        self.feed.config(state="disabled")
        self.status.config(text=f"blocks {blocks}  \u00b7  minted {minted:.2f} / "
                                f"{core.MAX_SUPPLY:,}  \u00b7  validators {validators}"
                                f"  \u00b7  peers {peers}"
                                + (f"  \u00b7  {len(pend)} awaiting votes" if pend else ""))
        self.root.after(2000, self.refresh)

    def close(self):
        self.node.mining = False
        self.root.destroy()


def main():
    if tk is None:
        print("tkinter is missing. Install Python from python.org (it includes it).")
        return
    port = 7000
    for arg in sys.argv[1:]:
        if arg.isdigit():
            port = int(arg)
    node = start_node(port)
    root = tk.Tk()
    WalletApp(root, node)
    root.mainloop()


if __name__ == "__main__":
    main()
