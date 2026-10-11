"""
Hybrid session-key derivation: BB84 (QKD) key + ML-KEM-768 shared secret.

The wrap key stays secret if EITHER ingredient is secure. This removes the
single-point-of-trust problem of relying on a simulated QKD link alone.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_hybrid_key(qkd_key: bytes, kem_shared_secret: bytes,
                      context: bytes = b"shorlynot-hybrid-v1") -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context,
    ).derive(len(qkd_key).to_bytes(2, "big") + qkd_key + kem_shared_secret)
