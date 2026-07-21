"""
Recovery phrases for Sosaiem wallets.

A wallet is a post-quantum ML-DSA-65 key. Losing the key file means losing the
coins for good -- there is no company to ask and no reset link. A recovery
phrase is simply that key written as words you can put on paper.

How it works here:

  * 16 random bytes (128 bits) are the real secret.
  * Each byte is written as one word from a fixed 256-word list, so the phrase
    is 16 words, plus a 17th checksum word that catches a mistyped or
    mis-ordered phrase before it silently hands you the wrong wallet.
  * Those 16 bytes are stretched to the 32-byte seed ML-DSA needs, and the
    keypair is derived from it. Same phrase in, same wallet out, forever.

One byte per word means there is no bit-packing to get subtly wrong, and the
phrase can be checked by eye against the list.

This is deliberately NOT BIP-39. BIP-39 describes Bitcoin's elliptic-curve key
derivation; ML-DSA keys are a different shape entirely, so no BIP-39 tool could
restore a Sosaiem wallet regardless of which words were used. Pretending to be
compatible would be worse than being plainly different.
"""

import hashlib
import os


# 256 short words, one per byte value. Every word has a distinct first three
# letters so a smudged or half-remembered word is still unambiguous.
# THIS LIST MUST NEVER CHANGE -- every phrase ever written down depends on it.
_RAW_WORDS = """
able acid aged also amber arch army atom aunt axis baby back bake ball band
bank bare barn base bath bead beam bean bear beef bell belt bend best bike
bird bite blue boat body boil bold bone book boot born both bowl brew bulk
bush busy cabin cage cake calm camp cane cargo cart case cave cedar cell
chain chef chin city civic claim clay clean cliff cloud coal coast code coin
cold comet cool copper coral cost cotton cove crane crop crow cube cup curl
cycle daisy damp dark dawn deal debt deck deep deer delta dense desk dial
dice diet dish dive dock dome door dove down draft dream drift drum dry duck
dune dusk duty eagle early earth east echo edge eight elbow elder elm ember
empty end envy equal even exact exit eye fable face fact fade fair fall fan
farm fast fault fawn feast fern few fiber field fig film find fine fire fish
five flag flame flash fleet flint float flow fluid foam focus fog fold food
fork form fort found fox frame free fresh frog front frost fruit fuel full
fun fuse gain gap garden gate gauge gear gem gentle ghost giant gift ginger
give glad glass globe glow goat gold good grain grand grape grass gray green
grid grove guard guess guide gulf gust habit hail hair half hall hand harbor
hard harp haste hawk hay hazel head heart heat hedge help hemp herb hero hill
hinge hint hive hold hollow honey hood hook hope horn horse host hour hub
human hunt hut ice idea idle inch index ink inlet iron island ivory ivy jade
jar jaw jelly jet jewel join joy judge juice jump keel keen kelp key kind
king kite knee knife knot lace lake lamp land lane large last late lava lawn
layer lead leaf lean leap ledge left legend lemon lens level lever light lily
lime line lion list live loaf lock lodge log long loop lord loud love low
loyal luck lung lynx magnet maize major maple marble march mark mask mast
match maze meadow melt mercy mesh metal meter mild milk mill mint mirror mist
mix moat model moist mold moment monk moon moss moth motor mount mouse move
much mud music mute nail name near neck nest net never new next night nine
noble node noise north nose note novel now oak oat ocean odd offer often oil
old olive onion open opera orbit orchid order organ otter oven owl own oxide
pace pack page pain paint pair palm panel paper park part patch path pause
peace peak pearl pebble pen pepper perch petal photo piano pick pier pilot
pine pink pipe pitch place plain plane plant plate play plum point polar pond
pool porch port post pot pouch power prairie press price pride prime print
prism prize proof proud pulse pump pure purple push quarry queen quest quick
quiet quilt quote radar radio raft rail rain raise ranch range rapid rare
raven reach ready realm reason reed reef relay rest ribbon rice ridge rifle
rim ring rise river road robin rock rod roof room root rope rose round row
royal ruby rug rule rush rust sable saddle safe sage sail salt sand sash
sauce scale scarf scene school scope score scout seal seat sedge seed sense
"""


def _build_wordlist():
    seen_prefix, out = set(), []
    for w in _RAW_WORDS.split():
        if not w.isalpha() or not (3 <= len(w) <= 7):
            continue
        p = w[:3]
        if p in seen_prefix:
            continue
        seen_prefix.add(p)
        out.append(w)
        if len(out) == 256:
            break
    return out


WORDS = _build_wordlist()
_INDEX = {w: i for i, w in enumerate(WORDS)}
_PREFIX = {w[:3]: i for i, w in enumerate(WORDS)}

ENTROPY_BYTES = 16
PHRASE_LENGTH = ENTROPY_BYTES + 1          # 16 words + 1 checksum word
_DOMAIN = b"SOSAIEM-recovery-v1|ML-DSA-65|"


class PhraseError(ValueError):
    """A recovery phrase was not understandable or did not check out."""


def _checksum_byte(entropy: bytes) -> int:
    return hashlib.sha256(_DOMAIN + entropy).digest()[0]


def entropy_to_phrase(entropy: bytes) -> str:
    if len(entropy) != ENTROPY_BYTES:
        raise PhraseError(f"need {ENTROPY_BYTES} bytes of entropy")
    words = [WORDS[b] for b in entropy]
    words.append(WORDS[_checksum_byte(entropy)])
    return " ".join(words)


def phrase_to_entropy(phrase: str) -> bytes:
    raw = [w for w in str(phrase).replace(",", " ").lower().split() if w]
    if len(raw) != PHRASE_LENGTH:
        raise PhraseError(
            f"a recovery phrase is {PHRASE_LENGTH} words -- this one has {len(raw)}")
    idx = []
    for w in raw:
        if w in _INDEX:
            idx.append(_INDEX[w])
        elif w[:3] in _PREFIX:                 # tolerate a misspelt tail
            idx.append(_PREFIX[w[:3]])
        else:
            raise PhraseError(f"'{w}' is not a Sosaiem recovery word")
    entropy = bytes(idx[:ENTROPY_BYTES])
    if idx[ENTROPY_BYTES] != _checksum_byte(entropy):
        raise PhraseError(
            "those are all real words, but the phrase does not check out -- "
            "a word is probably wrong or out of order")
    return entropy


def new_phrase() -> str:
    return entropy_to_phrase(os.urandom(ENTROPY_BYTES))


def phrase_to_seed(phrase: str) -> bytes:
    """The 32-byte seed ML-DSA-65 keygen takes."""
    return hashlib.sha256(_DOMAIN + phrase_to_entropy(phrase)).digest()


def looks_like_phrase(text: str) -> bool:
    try:
        phrase_to_entropy(text)
        return True
    except Exception:
        return False


# --- deriving the actual ML-DSA keypair from that seed -----------------------

def keypair_from_seed(mldsa, seed: bytes):
    """
    Derive an ML-DSA keypair deterministically from a 32-byte seed.

    dilithium-py has changed the name of its seeded key generation between
    releases, so rather than bet on one spelling we try each known form and
    then *prove* the result is deterministic before returning it. If a future
    version breaks all of them we raise loudly -- handing someone a recovery
    phrase that silently fails to restore would be far worse than an error.
    """
    if len(seed) != 32:
        raise PhraseError("ML-DSA-65 needs a 32-byte seed")

    def attempt():
        for name in ("_keygen_internal", "keygen_internal", "key_derive", "keygen_from_seed"):
            fn = getattr(mldsa, name, None)
            if callable(fn):
                try:
                    return fn(seed)
                except Exception:
                    continue
        # last resort: feed the library's own randomness source from the seed
        if hasattr(mldsa, "random_bytes"):
            original = mldsa.random_bytes
            try:
                stream = _SeedStream(seed)
                mldsa.random_bytes = stream.read
                return mldsa.keygen()
            except Exception:
                return None
            finally:
                mldsa.random_bytes = original
        return None

    first = attempt()
    if not first:
        raise PhraseError(
            "this build of dilithium-py does not expose seeded key generation, "
            "so recovery phrases cannot be used with it")
    second = attempt()
    if not second or bytes(first[0]) != bytes(second[0]):
        raise PhraseError(
            "key derivation from a seed is not repeatable in this build of "
            "dilithium-py -- refusing to issue a recovery phrase that would "
            "not restore the same wallet")
    return first


class _SeedStream:
    """A deterministic byte stream expanded from the seed."""

    def __init__(self, seed: bytes):
        self._seed, self._n = seed, 0

    def read(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            out += hashlib.sha256(self._seed + self._n.to_bytes(8, "big")).digest()
            self._n += 1
        return out[:n]


if __name__ == "__main__":
    print(f"wordlist: {len(WORDS)} words, all unique: {len(set(WORDS)) == len(WORDS)}")
    p = new_phrase()
    print("example phrase:\n  " + p)
    print("round-trips:", entropy_to_phrase(phrase_to_entropy(p)) == p)
