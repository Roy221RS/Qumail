"""
crypto_adapter.py

Level 1: passthrough (no encryption).
Level 2: HKDF-derived AES-256-GCM.
    The raw QKD key (1KB from km_adapter.py) is NOT used directly as the
    AES key - it's run through HKDF to deterministically derive a proper
    32-byte AES-256 key. "Deterministic" is the key property: sender and
    receiver independently fetch the SAME raw key bytes from their own
    local KM, run the SAME derivation, and land on the SAME AES key -
    without ever exchanging the derived key itself.
    AES-256-GCM also gives integrity for free: a tampered/corrupted
    ciphertext fails the auth-tag check and raises, instead of silently
    decrypting into garbage.
Level 3: One-Time Pad (XOR) - not implemented yet, raises NotImplementedError.
    Coming next: raw key bytes used directly as the pad, no derivation,
    no reuse allowed.

Key FETCHING lives in km_adapter.py - this class only does the crypto
transform, given key bytes it's handed by the caller (email_engine.py).
Keeps the two concerns swappable independently.
"""

import os
import base64
from typing import Optional, Tuple, Dict, Any

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

AES_KEY_LEN = 32          # AES-256 requires exactly a 32-byte key
GCM_NONCE_LEN = 12        # standard/recommended nonce size for AES-GCM
# Fixed context string for HKDF - must be identical on both sender and
# receiver, since it's part of what determines the derived key. Not
# secret, just needs to match.
HKDF_INFO_L2 = b"qumail-level2-aes-gcm"


def _derive_aes_key(raw_key_material: bytes) -> bytes:
    """HKDF: turn the raw QKD key bytes into a proper 32-byte AES-256 key.
    Deterministic - same input always produces the same output."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LEN,
        salt=None,
        info=HKDF_INFO_L2,
    )
    return hkdf.derive(raw_key_material)


class CryptoAdapter:
    def encrypt_payload(
        self,
        payload_bytes: bytes,
        level: int = 1,
        key_material: Optional[bytes] = None,
        key_id: Optional[str] = None,
    ) -> Tuple[bytes, Dict[str, Any]]:
        if level == 1:
            return payload_bytes, {"level": 1, "key_id": None}

        if level == 2:
            if not key_material:
                raise ValueError("Level 2 encryption requires key_material from the KM.")
            aes_key = _derive_aes_key(key_material)
            nonce = os.urandom(GCM_NONCE_LEN)
            ciphertext = AESGCM(aes_key).encrypt(nonce, payload_bytes, associated_data=None)
            return ciphertext, {
                "level": 2,
                "key_id": key_id,
                "nonce": base64.b64encode(nonce).decode("ascii"),
            }

        # Level 3 (OTP/XOR) - next up, not yet implemented.
        raise NotImplementedError(f"Security level {level} not implemented yet.")

    def decrypt_payload(
        self,
        processed_bytes: bytes,
        metadata_dict: Dict[str, Any],
        key_material: Optional[bytes] = None,
    ) -> bytes:
        level = metadata_dict.get("level", 1)
        if level == 1:
            return processed_bytes

        if level == 2:
            if not key_material:
                raise ValueError("Level 2 decryption requires key_material from the KM.")
            nonce_b64 = metadata_dict.get("nonce")
            if not nonce_b64:
                raise ValueError(
                    "Level 2 decryption requires a nonce (missing X-QuMail-Nonce header)."
                )
            nonce = base64.b64decode(nonce_b64)
            aes_key = _derive_aes_key(key_material)
            try:
                return AESGCM(aes_key).decrypt(nonce, processed_bytes, associated_data=None)
            except InvalidTag as e:
                raise ValueError(
                    "Decryption failed: wrong key or tampered/corrupted message."
                ) from e

        raise NotImplementedError(f"Security level {level} not implemented yet.")