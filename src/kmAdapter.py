import os
import json
import base64
import random
from abc import ABC, abstractmethod
from typing import Optional, Tuple, Dict

NUM_KEYS = 100
KEY_SIZE_BYTES = 1024  # 1 KB per key, per the problem statement's starting bank size

# NOTE: a fixed seed is what makes two independently-run mock KMs agree on
# key material without talking to each other. Change this only if you
# intentionally want a fresh, non-matching key bank (e.g. testing exhaustion).
DEFAULT_SEED = 20260004  # arbitrary, doubles as a nod to the SIH problem statement number

KEY_BANK_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "key_bank.json"
)


class KMAdapter(ABC):
    """Interface every Key Manager adapter must implement (mock or real)."""

    @abstractmethod
    def get_status(self) -> Dict[str, int]:
        """Return {'total_keys', 'used_keys', 'available_keys'}."""
        raise NotImplementedError

    @abstractmethod
    def get_key(self, key_id: Optional[str] = None) -> Tuple[bytes, str]:
        """
        Sender side: call with key_id=None to allocate a fresh unused key.
            Returns (key_bytes, newly_allocated_key_id).
        Receiver side: call with a specific key_id (from the X-QuMail-KeyID
            header) to fetch that exact key's bytes.
            Returns (key_bytes, key_id) - same key_id echoed back.
        Raises KeyError if a given key_id doesn't exist, RuntimeError if
        the bank is exhausted (no unused keys left) when key_id=None.
        """
        raise NotImplementedError


class MockKMAdapter(KMAdapter):
    def __init__(
        self,
        path: str = KEY_BANK_PATH,
        seed: int = DEFAULT_SEED,
        num_keys: int = NUM_KEYS,
        key_size: int = KEY_SIZE_BYTES,
    ):
        self.path = path
        self.seed = seed
        self.num_keys = num_keys
        self.key_size = key_size
        # in-memory: key_id -> {"key": base64 str, "used": bool}
        self._bank: Dict[str, dict] = {}
        self._load_or_generate()

    # -- setup ---------------------------------------------------------- #
    def _generate_deterministic_bank(self) -> Dict[str, dict]:
        rng = random.Random(self.seed)
        bank = {}
        for i in range(1, self.num_keys + 1):
            key_id = f"KEY-{i:04d}"
            key_bytes = bytes(rng.getrandbits(8) for _ in range(self.key_size))
            bank[key_id] = {"key": base64.b64encode(key_bytes).decode("ascii"), "used": False}
        return bank

    def _load_or_generate(self) -> None:
        """Load an existing on-disk bank (so 'used' state survives app
        restarts) or generate a fresh deterministic one on first run."""
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self._bank = json.load(f)
                if self._bank:
                    return
            except (json.JSONDecodeError, OSError):
                pass  # fall through to regenerate
        self._bank = self._generate_deterministic_bank()
        self._save()

    def _save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._bank, f)

    # -- public API ------------------------------------------------------ #
    def get_status(self) -> Dict[str, int]:
        total = len(self._bank)
        used = sum(1 for entry in self._bank.values() if entry["used"])
        return {"total_keys": total, "used_keys": used, "available_keys": total - used}

    def get_key(self, key_id: Optional[str] = None) -> Tuple[bytes, str]:
        if key_id is not None:
            entry = self._bank.get(key_id)
            if entry is None:
                raise KeyError(f"Unknown key_id: {key_id!r} (not in local key bank)")
            # Mark used on the receiving side too - a key that's been
            # consumed for OTP/AES on either end shouldn't be reused, since
            # reuse breaks the security guarantee QKD is supposed to give.
            entry["used"] = True
            self._save()
            return base64.b64decode(entry["key"]), key_id

        # Sender side: allocate the first unused key in the bank.
        for kid, entry in self._bank.items():
            if not entry["used"]:
                entry["used"] = True
                self._save()
                return base64.b64decode(entry["key"]), kid

        raise RuntimeError(
            "Key bank exhausted: no unused keys remaining. "
            "Fall back to a lower security level or reset the bank."
        )

    # -- convenience for demo/testing ------------------------------------ #
    def reset(self) -> None:
        """Regenerate the bank from scratch (all keys unused again).
        Since generation is deterministic, this restores the SAME key
        material - only the 'used' flags are cleared. Useful for demo
        resets, not something a real KM would ever expose."""
        self._bank = self._generate_deterministic_bank()
        self._save()
