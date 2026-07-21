"""
Finding the network without asking anyone's permission.

A brand-new node has to learn one address from somewhere. If that somewhere is
a file on a website, then whoever owns the website is a person the network
depends on -- and a coin that depends on a person is not really leaderless, no
matter what the whitepaper says.

Nostr fixes that. It is a small protocol for publishing signed messages to
relays: public servers run by dozens of unrelated people, free to use, needing
no account and no approval. A Sosaiem node that can accept incoming connections
announces itself to several of them. A new node asks those relays who is out
there. Nobody owns the rendezvous, and if every relay listed here vanished,
anyone could add their own without changing the coin.

Everything is the Python standard library. No pip install -- telling a beginner
to install packages is its own kind of gatekeeping.

Two things are implemented by hand because Python ships neither:
  * BIP-340 Schnorr signatures over secp256k1, which Nostr requires. These are
    checked against the official test vectors -- run this file to see.
  * A minimal WebSocket client, since relays speak WebSocket.
"""

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import time
import urllib.parse

# Relays run by unrelated operators. If some are down, slow or hostile, the
# others still work -- that is the whole point. Anyone may edit this list.
DEFAULT_RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
    "wss://nostr.mom",
    "wss://relay.primal.net",
]

KIND = 30078          # "application-specific data", replaceable
TAG = "sosaiem-node"


# --------------------------------------------------------------------------
# secp256k1 and BIP-340 Schnorr
# --------------------------------------------------------------------------

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = 3 * p1[0] * p1[0] * pow(2 * p1[1], _P - 2, _P) % _P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], _P - 2, _P) % _P
    x3 = (lam * lam - p1[0] - p2[0]) % _P
    return (x3, (lam * (p1[0] - x3) - p1[1]) % _P)


def _mul(p, n):
    r = None
    while n:
        if n & 1:
            r = _add(r, p)
        p = _add(p, p)
        n >>= 1
    return r


def _tagged(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def pubkey_xonly(seckey: bytes) -> bytes:
    """The 32-byte x-only public key Nostr uses as an identity."""
    d = int.from_bytes(seckey, "big")
    if not 1 <= d < _N:
        raise ValueError("secret key out of range")
    return _mul(_G, d)[0].to_bytes(32, "big")


def schnorr_sign(msg32: bytes, seckey: bytes, aux: bytes = None) -> bytes:
    if len(msg32) != 32:
        raise ValueError("message must be 32 bytes")
    d0 = int.from_bytes(seckey, "big")
    if not 1 <= d0 < _N:
        raise ValueError("secret key out of range")
    P = _mul(_G, d0)
    d = d0 if P[1] % 2 == 0 else _N - d0
    if aux is None:
        aux = os.urandom(32)
    t = d ^ int.from_bytes(_tagged("BIP0340/aux", aux), "big")
    rand = _tagged("BIP0340/nonce",
                   t.to_bytes(32, "big") + P[0].to_bytes(32, "big") + msg32)
    k0 = int.from_bytes(rand, "big") % _N
    if k0 == 0:
        raise ValueError("bad nonce")
    R = _mul(_G, k0)
    k = k0 if R[1] % 2 == 0 else _N - k0
    e = int.from_bytes(_tagged("BIP0340/challenge",
                               R[0].to_bytes(32, "big")
                               + P[0].to_bytes(32, "big") + msg32), "big") % _N
    return R[0].to_bytes(32, "big") + ((k + e * d) % _N).to_bytes(32, "big")


def schnorr_verify(msg32: bytes, pubkey: bytes, sig: bytes) -> bool:
    """Used to check other nodes' announcements before trusting an address."""
    try:
        if len(sig) != 64 or len(pubkey) != 32 or len(msg32) != 32:
            return False
        x = int.from_bytes(pubkey, "big")
        if x >= _P:
            return False
        y_sq = (pow(x, 3, _P) + 7) % _P
        y = pow(y_sq, (_P + 1) // 4, _P)
        if pow(y, 2, _P) != y_sq:
            return False
        P = (x, y if y % 2 == 0 else _P - y)
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        if r >= _P or s >= _N:
            return False
        e = int.from_bytes(_tagged("BIP0340/challenge",
                                   sig[:32] + pubkey + msg32), "big") % _N
        R = _add(_mul(_G, s), _mul((P[0], _P - P[1]), e))
        return R is not None and R[1] % 2 == 0 and R[0] == r
    except Exception:
        return False


# --------------------------------------------------------------------------
# A very small WebSocket client
# --------------------------------------------------------------------------

class WebSocket:
    def __init__(self, url, timeout=8):
        u = urllib.parse.urlparse(url)
        secure = u.scheme == "wss"
        port = u.port or (443 if secure else 80)
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        self.sock = socket.create_connection((u.hostname, port), timeout=timeout)
        if secure:
            self.sock = ssl.create_default_context().wrap_socket(
                self.sock, server_hostname=u.hostname)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall(
            (f"GET {path} HTTP/1.1\r\nHost: {u.hostname}\r\n"
             "Upgrade: websocket\r\nConnection: Upgrade\r\n"
             f"Sec-WebSocket-Key: {key}\r\n"
             "Sec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("relay closed during handshake")
            head += chunk
            if len(head) > 65536:
                raise ConnectionError("relay sent nonsense")
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise ConnectionError("relay refused the connection")
        self._buf = head.split(b"\r\n\r\n", 1)[1]

    def send(self, text):
        payload = text.encode()
        mask = os.urandom(4)
        n = len(payload)
        header = bytearray([0x81])
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        header += mask
        self.sock.sendall(bytes(header)
                          + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def _read(self, n):
        while len(self._buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("relay closed")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def recv(self):
        b0, b1 = self._read(2)
        opcode = b0 & 0x0F
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._read(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._read(8))[0]
        if length > 4_000_000:
            raise ConnectionError("relay sent an oversized frame")
        if b1 & 0x80:
            mask = self._read(4)
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(self._read(length)))
        else:
            data = self._read(length)
        if opcode == 0x8:
            raise ConnectionError("relay closed")
        if opcode == 0x9:                       # ping -> pong
            self.sock.sendall(b"\x8a\x80" + os.urandom(4))
            return self.recv()
        return data.decode(errors="ignore")

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# Announcing and finding Sosaiem nodes
# --------------------------------------------------------------------------

def _serialize(pub, created, tags, content):
    return json.dumps([0, pub, created, KIND, tags, content],
                      separators=(",", ":"), ensure_ascii=False)


def build_event(seckey, url, genesis, created=None):
    pub = pubkey_xonly(seckey).hex()
    created = int(created if created is not None else time.time())
    tags = [["d", TAG], ["genesis", genesis]]
    eid = hashlib.sha256(_serialize(pub, created, tags, url).encode()).digest()
    return {"id": eid.hex(), "pubkey": pub, "created_at": created, "kind": KIND,
            "tags": tags, "content": url, "sig": schnorr_sign(eid, seckey).hex()}


def event_is_valid(ev, genesis):
    """Check an announcement really came from whoever signed it."""
    try:
        pub = ev["pubkey"]
        tags = ev.get("tags", [])
        eid = hashlib.sha256(
            _serialize(pub, int(ev["created_at"]), tags,
                       ev.get("content", "")).encode()).digest()
        if eid.hex() != ev.get("id"):
            return False
        flat = {t[0]: t[1] for t in tags if isinstance(t, list) and len(t) >= 2}
        if flat.get("genesis") != genesis:
            return False              # a different coin's announcement
        return schnorr_verify(eid, bytes.fromhex(pub), bytes.fromhex(ev["sig"]))
    except Exception:
        return False


def announce(seckey, url, genesis, relays=None, timeout=8):
    """Tell the relays this node is reachable. Returns how many accepted it."""
    ev = build_event(seckey, url, genesis)
    msg = json.dumps(["EVENT", ev])
    ok = 0
    for relay in (relays or DEFAULT_RELAYS):
        ws = None
        try:
            ws = WebSocket(relay, timeout=timeout)
            ws.send(msg)
            reply = json.loads(ws.recv())
            if reply and reply[0] == "OK" and (len(reply) < 3 or reply[2]):
                ok += 1
        except Exception:
            pass
        finally:
            if ws:
                ws.close()
    return ok


def discover(genesis, relays=None, timeout=8, want=40):
    """Ask the relays which Sosaiem nodes have announced themselves."""
    found = []
    req = json.dumps(["REQ", "sos",
                      {"kinds": [KIND], "#d": [TAG], "limit": want}])
    for relay in (relays or DEFAULT_RELAYS):
        ws = None
        try:
            ws = WebSocket(relay, timeout=timeout)
            ws.send(req)
            deadline = time.time() + timeout
            while time.time() < deadline:
                msg = json.loads(ws.recv())
                if not msg:
                    continue
                if msg[0] == "EOSE":
                    break
                if msg[0] != "EVENT" or len(msg) < 3:
                    continue
                ev = msg[2]
                if not event_is_valid(ev, genesis):
                    continue
                u = str(ev.get("content", "")).strip().rstrip("/")
                if u.startswith("http") and u not in found:
                    found.append(u)
        except Exception:
            pass
        finally:
            if ws:
                ws.close()
        if len(found) >= want:
            break
    return found


def identity_from(secret: bytes) -> bytes:
    """A stable Nostr key for this node, derived from something it already has."""
    d = hashlib.sha256(b"sosaiem-nostr-identity|" + secret).digest()
    n = int.from_bytes(d, "big") % (_N - 1) + 1
    return n.to_bytes(32, "big")


# Official BIP-340 vectors. If these fail nothing else here can be trusted.
_VECTORS = [
    ("0000000000000000000000000000000000000000000000000000000000000003",
     "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
     "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
    ("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
     "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "0000000000000000000000000000000000000000000000000000000000000001",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
     "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"),
    ("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
     "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
     "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
     "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
     "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B"
     "AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7"),
]


def self_test(verbose=True):
    ok = True
    for sk, pk, aux, msg, sig in _VECTORS:
        got_pk = pubkey_xonly(bytes.fromhex(sk)).hex().upper()
        got_sig = schnorr_sign(bytes.fromhex(msg), bytes.fromhex(sk),
                               bytes.fromhex(aux)).hex().upper()
        good = schnorr_verify(bytes.fromhex(msg), bytes.fromhex(pk),
                              bytes.fromhex(sig))
        if verbose:
            print(f"  pubkey {'OK' if got_pk == pk else 'FAIL'}   "
                  f"sign {'OK' if got_sig == sig else 'FAIL'}   "
                  f"verify {'OK' if good else 'FAIL'}")
        ok = ok and got_pk == pk and got_sig == sig and good
    return ok


if __name__ == "__main__":
    print("BIP-340 official test vectors:")
    print("all correct" if self_test() else "SIGNATURES ARE WRONG -- do not ship")
