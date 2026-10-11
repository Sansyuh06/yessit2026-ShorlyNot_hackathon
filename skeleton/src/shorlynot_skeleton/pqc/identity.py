"""
ML-DSA-44 (NIST FIPS 204) identity signatures via `dilithium-py`.

Binds a signature bundle's header (payload hash, nonce, key id, parameters)
to a registered public key. This is what makes "who signed" cryptographic
evidence instead of a label the sender controls.
"""

import hashlib
from typing import Optional, Tuple

from dilithium_py.ml_dsa import ML_DSA_44

ALGORITHM_NAME = "ML-DSA-44 (FIPS 204) via dilithium-py"


def identity_message(payload_hash: str, nonce: str, key_id: str, n_checks: int, L: int) -> bytes:
    return hashlib.sha256(
        f"shorlynot-id-v1|{payload_hash}|{nonce}|{key_id}|{n_checks}|{L}".encode()
    ).digest()


def keygen() -> Tuple[bytes, bytes]:
    return ML_DSA_44.keygen()


def sign(secret_key: bytes, message: bytes) -> bytes:
    return ML_DSA_44.sign(secret_key, message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        return bool(ML_DSA_44.verify(public_key, message, signature))
    except Exception:
        return False
