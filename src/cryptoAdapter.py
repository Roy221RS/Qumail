import os
import base64
from typing import Optional, Tuple, Dict, Any

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

AES_KEY_LEN = 32
GCM_NONCE_LEN = 12
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

        if level == 3:
            if not key_material:
                raise ValueError("Level 3 encryption requires key_material from the KM.")
            if len(payload_bytes) > len(key_material):
                raise ValueError(
                    f"Message ({len(payload_bytes)} bytes) exceeds available key "
                    f"material ({len(key_material)} bytes) for Level 3 OTP. "
                    "Shorten the message or use Level 2 instead."
                )
            # Raw XOR - no derivation. OTP security requires the pad be
            # used exactly as-is: truly random, at least as long as the
            # message, and never reused (km_adapter marks it used on fetch).
            ciphertext = bytes(p ^ k for p, k in zip(payload_bytes, key_material))
            return ciphertext, {"level": 3, "key_id": key_id}

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

        if level == 3:
            if not key_material:
                raise ValueError("Level 3 decryption requires key_material from the KM.")
            if len(processed_bytes) > len(key_material):
                raise ValueError(
                    f"Ciphertext ({len(processed_bytes)} bytes) exceeds available key "
                    f"material ({len(key_material)} bytes) - cannot be valid OTP data."
                )
            return bytes(c ^ k for c, k in zip(processed_bytes, key_material))

        raise NotImplementedError(f"Security level {level} not implemented yet.")