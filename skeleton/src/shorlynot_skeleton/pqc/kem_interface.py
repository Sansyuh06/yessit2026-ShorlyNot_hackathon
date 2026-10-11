"""
Real ML-KEM-768 (NIST FIPS 203) via the `kyber-py` package.

Note: kyber-py is a pure-Python reference implementation. It is correct
(FIPS 203 sizes and KATs) but not constant-time, so it is suitable for a
research prototype, not a production deployment. For production, swap the
backend for liboqs; the interface below does not change.
"""

from typing import Tuple

from kyber_py.ml_kem import ML_KEM_768


class MlKem768Interface:
    ALGORITHM_NAME = "ML-KEM-768 (FIPS 203) via kyber-py"
    PUBLIC_KEY_SIZE = 1184
    CIPHERTEXT_SIZE = 1088
    SHARED_SECRET_SIZE = 32

    @classmethod
    def keypair(cls) -> Tuple[bytes, bytes]:
        """Return (public_key, secret_key)."""
        return ML_KEM_768.keygen()

    @classmethod
    def encapsulate(cls, public_key: bytes) -> Tuple[bytes, bytes]:
        """Return (ciphertext, shared_secret)."""
        shared_secret, ciphertext = ML_KEM_768.encaps(public_key)
        return ciphertext, shared_secret

    @classmethod
    def decapsulate(cls, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Return the shared secret. Tampered ciphertexts yield an unrelated
        secret (implicit rejection, as FIPS 203 specifies)."""
        if len(ciphertext) != cls.CIPHERTEXT_SIZE:
            raise ValueError("Invalid ciphertext length for ML-KEM-768")
        return ML_KEM_768.decaps(secret_key, ciphertext)
