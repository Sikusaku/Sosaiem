"""Sosaiem Wallet -- create your address, hold SOSA, send it. Native window, no browser."""

import os
import sys
import threading
import webbrowser

try:
    import tkinter as tk
    from tkinter import simpledialog, messagebox
except Exception:
    tk = None
    simpledialog = messagebox = None

import sosaiem_node as core
from wallet import Wallet

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


def start_node(port, password=None):
    # Only load wallet + chain and open the port here. The network threads are
    # started later, AFTER the window is on screen -- see main(). Running them
    # before the GUI draws was what made the app fail to open once saved files
    # existed: the heavy chain check plus network churn starved the window.
    node = core.Node(port, wallet_password=password)
    core.start_server(node)
    return node


def start_node_network(node):
    threading.Thread(target=core.auto_sync_loop, args=(node,), daemon=True).start()
    threading.Thread(target=core.discovery_beacon, args=(node,), daemon=True).start()
    threading.Thread(target=core.discovery_listener, args=(node,), daemon=True).start()
    threading.Thread(target=core.load_seeds, args=(node,), daemon=True).start()


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
        tk.Label(root, text=f"version {core.NODE_VERSION}",
                 bg=PLATE, fg=SAGE, font=("Consolas", 8)).pack(pady=(2, 0))

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

        backup = tk.Frame(root, bg=PLATE)
        backup.pack(fill="x", padx=22, pady=(6, 12))
        # Buttons live on their own row; the hint text goes on a full-width line
        # BELOW them. Packing all of it side-by-side made the italic hint run
        # into the buttons on a narrow window -- the overlap people were seeing.
        row = tk.Frame(backup, bg=PLATE)
        row.pack(fill="x", anchor="w")
        if node.wallet.has_phrase():
            tk.Button(row, text="Show recovery phrase", command=self.show_phrase,
                      bg=PANEL, fg=GILT, relief="flat", font=("Consolas", 9),
                      cursor="hand2").pack(side="left")
            tk.Button(row, text="Set password", command=self.set_password,
                      bg=PANEL, fg=GILT, relief="flat", font=("Consolas", 9),
                      cursor="hand2").pack(side="left", padx=(10, 0))
            tk.Button(row, text="Block explorer", command=self.open_explorer,
                      bg=PANEL, fg=GILT2, relief="flat", font=("Consolas", 9),
                      cursor="hand2").pack(side="left", padx=(10, 0))
            tk.Label(backup, text="write the words down \u2014 they are the only way back",
                     bg=PLATE, fg=DIM, font=("Georgia", 9, "italic"),
                     anchor="w").pack(fill="x", anchor="w", pady=(4, 0))
        else:
            tk.Button(row, text="Block explorer", command=self.open_explorer,
                      bg=PANEL, fg=GILT2, relief="flat", font=("Consolas", 9),
                      cursor="hand2").pack(side="left")
            tk.Label(backup, text=f"No recovery phrase \u2014 back up {node.wallet_file}, "
                                  "that file IS your coins.",
                     bg=PLATE, fg=RED, font=("Georgia", 9, "italic"),
                     anchor="w").pack(fill="x", anchor="w", pady=(4, 0))

        root.protocol("WM_DELETE_WINDOW", self.close)
        self.refresh()

    def open_explorer(self):
        """
        Open the public block explorer in the browser so people can look up
        blocks and transfers straight from the wallet. Suggested by a miner --
        having the ledger one click away makes the coin easy to verify.
        """
        webbrowser.open("https://sosaiem.com/network.html")

    def set_password(self):
        """
        Lock the wallet file with a password.

        Until now anything that could read the folder owned the coins in it --
        the secret key and the recovery words sat there in plain text. A miner
        pointed this out and he was right.
        """
        pw = simpledialog.askstring("Sosaiem",
            "Choose a password for this wallet.\n\n"
            "It encrypts the key and your recovery words on disk.\n"
            "There is no way to reset it -- if you forget it, only your\n"
            "17 recovery words can bring the wallet back.",
            show="*", parent=self.root)
        if not pw:
            return
        again = simpledialog.askstring("Sosaiem", "Type it again:",
                                       show="*", parent=self.root)
        if again != pw:
            messagebox.showerror("Sosaiem", "They did not match.", parent=self.root)
            return
        try:
            self.node.wallet.save_to_file(self.node.wallet_file, password=pw)
            self.node.wallet_password = pw
            messagebox.showinfo("Sosaiem",
                "Wallet locked. You will be asked for this password "
                "next time you open it.", parent=self.root)
        except Exception as e:
            messagebox.showerror("Sosaiem", f"Could not lock the wallet: {e}",
                                 parent=self.root)

    def show_phrase(self):
        phrase = self.node.wallet.phrase
        if not phrase:
            return
        win = tk.Toplevel(self.root)
        win.title("Recovery phrase")
        win.configure(bg=PLATE)
        win.resizable(False, False)
        tk.Label(win, text="YOUR RECOVERY PHRASE", bg=PLATE, fg=GILT,
                 font=("Consolas", 10)).pack(padx=26, pady=(20, 4))
        tk.Label(win, text="Write these 17 words on paper, in order, and keep them somewhere\n"
                           "safe. They rebuild this wallet on any computer.\n"
                           "Anyone who reads them can take your coins \u2014 never type them\n"
                           "into a website and never photograph them.",
                 bg=PLATE, fg=DIM, font=("Georgia", 9), justify="left").pack(padx=26)
        box = tk.Frame(win, bg=PANEL)
        box.pack(padx=26, pady=14, fill="x")
        words = phrase.split()
        for r in range(0, len(words), 4):
            line = tk.Frame(box, bg=PANEL)
            line.pack(anchor="w", padx=14, pady=3)
            for i, w in enumerate(words[r:r + 4], start=r + 1):
                tk.Label(line, text=f"{i:2}. {w:<8}", bg=PANEL, fg=PAPER,
                         font=("Consolas", 11)).pack(side="left")

        def copy():
            self.root.clipboard_clear()
            self.root.clipboard_append(phrase)
            msg.config(text="copied \u2014 paste it somewhere safe, then clear your clipboard")

        tk.Button(win, text="Copy words", command=copy, bg=PANEL, fg=GILT,
                  relief="flat", font=("Consolas", 9), cursor="hand2").pack()
        msg = tk.Label(win, text="", bg=PLATE, fg=SAGE, font=("Consolas", 8))
        msg.pack(pady=(6, 18))

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
                                       f"{pend_out:.6f} sending")
        else:
            self.available.config(text="feeless \u00b7 send to anyone, online or not")
        self.feed.config(state="normal")
        self.feed.delete("1.0", "end")
        self.feed.insert("1.0", "\n".join(events) if events else "waiting for activity\u2026")
        self.feed.config(state="disabled")
        self.status.config(text=f"blocks {blocks}  \u00b7  minted {minted:.2f} / "
                                f"{core.MAX_SUPPLY:,}  \u00b7  validators {validators}"
                                f"  \u00b7  peers {peers}"
                                + (f"  \u00b7  {len(pend)} sending" if pend else ""))
        self.root.after(2000, self.refresh)

    def close(self):
        self.node.mining = False
        # actually release the port and stop background threads, otherwise the
        # node lingers after the window closes and blocks the next launch
        try:
            if getattr(self.node, "server", None):
                self.node.server.shutdown()
                self.node.server.server_close()
        except Exception:
            pass
        self.root.destroy()
        import os
        os._exit(0)


def ask_restore(port):
    """
    On a machine with no wallet yet, offer the way back in before we make a new
    one. This is the moment a person who lost a laptop actually arrives at, so
    it has to be here rather than buried in a menu.
    """
    wallet_file = f"wallet_{port}.pem"
    if os.path.exists(wallet_file):
        return
    win = tk.Tk()
    win.title("Sosaiem")
    win.configure(bg=PLATE)
    win.resizable(False, False)
    tk.Label(win, text="SOSAIEM", bg=PLATE, fg=GILT,
             font=("Georgia", 20)).pack(padx=34, pady=(24, 2))
    tk.Label(win, text="There is no wallet on this computer yet.",
             bg=PLATE, fg=PAPER, font=SERIF).pack(padx=34)
    tk.Label(win, text="If you already have a wallet elsewhere, type its 17 recovery\n"
                       "words below to bring it back. Otherwise make a fresh one.",
             bg=PLATE, fg=DIM, font=("Georgia", 9), justify="left").pack(padx=34, pady=(6, 12))
    entry = tk.Text(win, bg=PANEL, fg=PAPER, font=("Consolas", 10),
                    relief="flat", height=3, width=52, wrap="word")
    entry.pack(padx=34)
    msg = tk.Label(win, text="", bg=PLATE, fg=RED, font=("Consolas", 8), wraplength=380)
    msg.pack(padx=34, pady=(6, 0))
    row = tk.Frame(win, bg=PLATE)
    row.pack(padx=34, pady=(10, 24))

    def restore():
        text = entry.get("1.0", "end").strip()
        if not text:
            msg.config(text="type your 17 words first")
            return
        try:
            w = Wallet.from_phrase(text)
            w.save_to_file(wallet_file)
        except Exception as e:
            msg.config(text=str(e))
            return
        win.destroy()

    def fresh():
        win.destroy()

    tk.Button(row, text="Restore this wallet", command=restore, bg=PANEL, fg=GILT,
              relief="flat", font=MONO, cursor="hand2").pack(side="left", padx=(0, 10))
    tk.Button(row, text="Make a new wallet", command=fresh, bg=PANEL, fg=DIM,
              relief="flat", font=MONO, cursor="hand2").pack(side="left")
    win.mainloop()


def main():
    core._unfreeze_windows_console()
    if tk is None:
        print("tkinter is missing. Install Python from python.org (it includes it).")
        return
    port = 7000
    for arg in sys.argv[1:]:
        if arg.isdigit():
            port = int(arg)
    want_threads = core.threads_from_args()
    ask_restore(port)

    # If this wallet is locked, ask before anything else -- the node cannot even
    # start without the key. Three tries, then stop rather than loop forever.
    from wallet import Wallet as _W
    wallet_file = f"wallet_{port}.pem"
    password = None
    if os.path.exists(wallet_file) and _W.is_locked(wallet_file):
        for attempt in range(3):
            box = tk.Tk(); box.withdraw()
            pw = simpledialog.askstring(
                "Sosaiem", "This wallet is password protected.\n\nPassword:",
                show="*", parent=box)
            box.destroy()
            if pw is None:
                return                      # they cancelled; nothing to do
            try:
                _W.load_from_file(wallet_file, password=pw)
                password = pw
                break
            except Exception:
                if attempt == 2:
                    err = tk.Tk(); err.withdraw()
                    messagebox.showerror("Sosaiem", "Wrong password.", parent=err)
                    err.destroy()
                    return

    node = start_node(port, password)
    if want_threads:
        node.mine_threads = want_threads
    root = tk.Tk()
    WalletApp(root, node)
    root.after(1500, lambda: start_node_network(node))
    root.mainloop()


if __name__ == "__main__":
    main()
