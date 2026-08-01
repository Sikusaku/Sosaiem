"""
SOSAIEM -- the one app.  (Sosaiem 3.0, Stage 1: modern web UI)

Starts your Sosaiem node quietly in the background and opens the wallet in a
clean app window: a left sidebar (Mine / Send / Explorer / Node), an onboarding
flow (create a wallet or import a recovery phrase), and a live view of the chain.

The UI is served BY your own node on localhost -- so the app you're looking at
and the node holding the chain are the same program. Using it makes you a full,
decentralized node; the window is just its face.

No consensus changes vs 2.17.0: same chain, same genesis, same balances.

Run:  python sosaiem_app.py [port]
"""

import os
import sys
import threading
import time
import webbrowser

import sosaiem_node as core


def start_node(port):
    node = core.Node(port)
    core.start_server(node)
    return node


def start_node_network(node):
    threading.Thread(target=core.auto_sync_loop, args=(node,), daemon=True).start()
    threading.Thread(target=core.discovery_beacon, args=(node,), daemon=True).start()
    threading.Thread(target=core.discovery_listener, args=(node,), daemon=True).start()
    threading.Thread(target=core.load_seeds, args=(node,), daemon=True).start()
    # Keep re-sending our unconfirmed transfers until they land, so a single
    # failed gossip (busy seed, momentary disconnect) can't silently strand a
    # send that the app already reported as "sent".
    threading.Thread(target=core.rebroadcast_transfers, args=(node,), daemon=True).start()
    # Watchdog: detect when we've drifted onto a losing chain and force a resync,
    # so a miner can't quietly waste work on a fork the network will reject.
    threading.Thread(target=core.mining_watchdog, args=(node,), daemon=True).start()
    # Become a REACHABLE node: ask the router to forward our port (UPnP) and
    # confirm with a peer, so other people can join the network THROUGH this app.
    # Every app that succeeds is one less reason the network needs the founder's
    # seed -- this is what lets the seed eventually be switched off.
    threading.Thread(target=core.open_the_door, args=(node,), daemon=True).start()
    # Announce ourselves to the public relays (Nostr) so newcomers -- and the
    # website's node list -- can discover us without any central server.
    threading.Thread(target=core.nostr_announce_loop, args=(node,), daemon=True).start()


def _open_window(url):
    """Open the wallet UI in a dedicated app window if possible, else a tab."""
    import shutil
    import subprocess
    for exe in ("chrome", "google-chrome", "chromium", "msedge", "microsoft-edge"):
        path = shutil.which(exe)
        if path:
            try:
                subprocess.Popen([path, "--app=" + url, "--window-size=460,780"])
                return
            except Exception:
                pass
    if os.name == "nt":
        try:
            subprocess.Popen(["cmd", "/c", "start", "msedge", "--app=" + url])
            return
        except Exception:
            pass
    webbrowser.open(url)


def main():
    core._unfreeze_windows_console()
    port = 7001
    for arg in sys.argv[1:]:
        if arg.isdigit():
            port = int(arg)
    want = core.threads_from_args()

    print("  Starting your Sosaiem node...")
    node = start_node(port)
    if want:
        node.mine_threads = want

    url = "http://127.0.0.1:%d/" % port
    print("  Node is up. Opening the wallet at " + url)
    print("  (Keep this window open -- it's your node. Closing it stops the node.)")

    threading.Thread(target=lambda: (time.sleep(1.0), start_node_network(node)),
                     daemon=True).start()
    threading.Thread(target=lambda: (time.sleep(1.5), _open_window(url)),
                     daemon=True).start()

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n  Shutting down...")
        node.mining = False
        try:
            if getattr(node, "server", None):
                node.server.shutdown()
        except Exception:
            pass


if __name__ == "__main__":
    main()
