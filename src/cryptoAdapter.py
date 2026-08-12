from typing import Optional, Tuple, Dict, Any


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
        
        raise NotImplementedError(
            f"Security level {level} not implemented yet (Phase 2)."
        )

    def decrypt_payload(
        self,
        processed_bytes: bytes,
        metadata_dict: Dict[str, Any],
        key_material: Optional[bytes] = None,
    ) -> bytes:
        level = metadata_dict.get("level", 1)
        if level == 1:
            return processed_bytes

        raise NotImplementedError(
            f"Security level {level} not implemented yet (Phase 2)."
        )
