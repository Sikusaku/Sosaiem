"""Post-quantum wallet (ML-DSA-65): keygen, signing, verification, addresses."""

import hashlib
import json


from dilithium_py.ml_dsa import ML_DSA_65 as MLDSA
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes as _h
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class WalletLocked(Exception):
    """The wallet file is encrypted and no password was given."""


class WrongPassword(Exception):
    """The password did not open the wallet."""


def _key_from(password: str, salt: bytes) -> bytes:
    # 400k rounds: slow enough that guessing a weak password is painful, fast
    # enough that unlocking your own wallet is not.
    kdf = PBKDF2HMAC(algorithm=_h.SHA256(), length=32, salt=salt, iterations=400_000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def _seal(plaintext: str, password: str, salt: bytes) -> str:
    return Fernet(_key_from(password, salt)).encrypt(plaintext.encode()).decode()


def _unseal(sealed: str, password: str, salt: bytes) -> str:
    return Fernet(_key_from(password, salt)).decrypt(sealed.encode()).decode()

import seedphrase


class Wallet:
    def __init__(self, secret_key=None, public_key=None, phrase=None):
        self.phrase = phrase
        if secret_key is None or public_key is None:
            if phrase is None:
                self._pk, self._sk = MLDSA.keygen()
            else:
                self._pk, self._sk = seedphrase.keypair_from_seed(
                    MLDSA, seedphrase.phrase_to_seed(phrase))
        else:
            self._pk, self._sk = public_key, secret_key

    # -- recovery phrases ----------------------------------------------------

    @staticmethod
    def create_with_phrase():
        """
        A brand-new wallet plus the words that can bring it back.

        The phrase is generated first and the keys derived from it, so the
        words are guaranteed to rebuild this exact wallet -- never the other
        way round, which would let us hand someone a phrase that doesn't work.
        """
        phrase = seedphrase.new_phrase()
        w = Wallet(phrase=phrase)
        check = Wallet(phrase=phrase)
        if check.address() != w.address():
            raise seedphrase.PhraseError(
                "this wallet could not be rebuilt from its own phrase -- "
                "refusing to create it")
        return w, phrase

    @staticmethod
    def from_phrase(phrase: str):
        return Wallet(phrase=phrase)

    def has_phrase(self) -> bool:
        return bool(self.phrase)

    def public_key_bytes(self):
        return self._pk

    def public_key_hex(self):
        return self._pk.hex()

    def address(self):
        digest = hashlib.sha256(self._pk).hexdigest()
        return "SOSA" + digest[:40]

    def sign(self, message: str) -> str:
        signature = MLDSA.sign(self._sk, message.encode("utf-8"))
        return signature.hex()

    def save_to_file(self, filename: str, password: str = None):
        """
        Write the wallet out. With a password, the secret key and the recovery
        words are encrypted and the file is useless to anyone who copies it.

        Without one the file is plain text, which is how it has always worked --
        anything that could read the folder owned the coins in it. Existing
        wallets keep loading exactly as before, so nobody is locked out by this.
        """
        secret = json.dumps({
            "secret_key": self._sk.hex(),
            "recovery_phrase": self.phrase,
        })
        data = {"scheme": "ML-DSA-65", "public_key": self._pk.hex()}
        if password:
            salt = os.urandom(16)
            data["locked"] = True
            data["salt"] = salt.hex()
            data["sealed"] = _seal(secret, password, salt)
        else:
            data["secret_key"] = self._sk.hex()
            if self.phrase:
                data["recovery_phrase"] = self.phrase
        with open(filename, "w") as f:
            json.dump(data, f)

    @staticmethod
    def is_locked(filename: str) -> bool:
        """True if this wallet file needs a password."""
        try:
            with open(filename) as f:
                return bool(json.load(f).get("locked"))
        except Exception:
            return False

    @staticmethod
    def load_from_file(filename: str, password: str = None):
        with open(filename) as f:
            data = json.load(f)
        if data.get("locked"):
            if not password:
                raise WalletLocked("this wallet is password protected")
            try:
                inner = json.loads(_unseal(data["sealed"], password,
                                           bytes.fromhex(data["salt"])))
            except Exception:
                raise WrongPassword("wrong password")
            return Wallet(
                secret_key=bytes.fromhex(inner["secret_key"]),
                public_key=bytes.fromhex(data["public_key"]),
                phrase=inner.get("recovery_phrase"),
            )
        return Wallet(
            secret_key=bytes.fromhex(data["secret_key"]),
            public_key=bytes.fromhex(data["public_key"]),
            phrase=data.get("recovery_phrase"),
        )


def verify_signature(public_key_hex: str, message: str, signature_hex: str) -> bool:
    try:
        pk = bytes.fromhex(public_key_hex)
        sig = bytes.fromhex(signature_hex)
        return MLDSA.verify(pk, message.encode("utf-8"), sig)
    except Exception:
        return False


if __name__ == "__main__":
    print("Creating a POST-QUANTUM Sosaiem wallet (ML-DSA-65)...\n")
    w = Wallet()
    print("  Address:", w.address())
    print()

    pk_bytes = len(w.public_key_bytes())
    print(f"  Public key size : {pk_bytes} bytes  "
          f"(ECDSA was ~33 bytes -- post-quantum keys are much bigger)")

    message = "I am sending 5 SOSA to my friend"
    sig = w.sign(message)
    sig_bytes = len(bytes.fromhex(sig))
    print(f"  Signature size  : {sig_bytes} bytes  "
          f"(ECDSA was ~71 bytes -- this is the real cost of quantum-safety)")
    print()

    ok = verify_signature(w.public_key_hex(), message, sig)
    print("  Valid signature verifies?        ->", ok)

    tampered = verify_signature(w.public_key_hex(), "I am sending 500 SOSA instead", sig)
    print("  Tampered message rejected?       ->", (not tampered))

    w.save_to_file("pq_wallet_test.json")
    w2 = Wallet.load_from_file("pq_wallet_test.json")
    same = (w2.address() == w.address()) and verify_signature(
        w2.public_key_hex(), message, w2.sign(message))
    print("  Save/load keeps the same wallet? ->", same)

    print()
    if ok and not tampered and same:
        print("  SUCCESS: post-quantum signing works. Sosaiem can be quantum-safe.")
    else:
        print("  Something failed -- tell Claude the exact output and it'll fix it.")
