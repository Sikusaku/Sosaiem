"""Post-quantum wallet (ML-DSA-65): keygen, signing, verification, addresses."""

import hashlib
import json


from dilithium_py.ml_dsa import ML_DSA_65 as MLDSA

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

    def save_to_file(self, filename: str):
        data = {
            "scheme": "ML-DSA-65",
            "public_key": self._pk.hex(),
            "secret_key": self._sk.hex(),
        }
        if self.phrase:
            # the file already holds the secret key in the clear, so keeping the
            # phrase beside it adds no new exposure and means the wallet can
            # show you the words again if you didn't write them down
            data["recovery_phrase"] = self.phrase
        with open(filename, "w") as f:
            json.dump(data, f)

    @staticmethod
    def load_from_file(filename: str):
        with open(filename) as f:
            data = json.load(f)
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
