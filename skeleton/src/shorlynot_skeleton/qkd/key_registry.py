"""
Quantum Key Management and Registration Subsystem.
SIH 2026 PS 26141 — ShorlyNot-QDS-T1 Key Provisioning & Binding.

Manages the quantum key generation ceremony, binding classical user identities
to QKD session keys and QDS signature credentials.
"""

import hashlib
import time
import uuid
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from shorlynot_skeleton.qkd.bb84 import Bb84Simulator
from shorlynot_skeleton.pqc import identity as pqc_identity


class KeyRecord(BaseModel):
    key_id: str
    user_id: str
    role: str = "customer"
    qkd_session_id: str
    key_fingerprint: str
    qber: float = 0.02
    created_at: float = Field(default_factory=time.time)
    status: str = "active"
    dsa_public_key: str = ""  # hex ML-DSA-44 public key (identity binding)


class QuantumKeyRegistry:
    """
    Central registry for quantum digital signature (QDS) keys and QKD session bindings.
    """

    def __init__(self) -> None:
        self._keys: Dict[str, KeyRecord] = {}
        self._user_to_keys: Dict[str, List[str]] = {}
        self._simulator = Bb84Simulator()
        # Demo keystore: in production the secret half lives in the signer's HSM/device,
        # never in the verifier's registry.
        self._dsa_secret: Dict[str, bytes] = {}
        self._seed_default_keys()

    def _new_identity_key(self, key_id: str) -> str:
        pk, sk = pqc_identity.keygen()
        self._dsa_secret[key_id] = sk
        return pk.hex()

    def sign_identity(self, key_id: str, message: bytes) -> Optional[str]:
        sk = self._dsa_secret.get(key_id)
        return pqc_identity.sign(sk, message).hex() if sk else None

    def verify_identity(self, key_id: str, message: bytes, sig_hex: Optional[str]) -> bool:
        rec = self._keys.get(key_id)
        if not rec or not rec.dsa_public_key or not sig_hex or rec.status != "active":
            return False
        try:
            return pqc_identity.verify(bytes.fromhex(rec.dsa_public_key), message, bytes.fromhex(sig_hex))
        except ValueError:
            return False

    def identify_signer(self, message: bytes, sig_hex: Optional[str]) -> Optional[str]:
        """Return the registered key_id whose public key verifies this signature, if any.
        Cryptographic attribution: used to find who really signed an impersonated bundle."""
        if not sig_hex:
            return None
        for key_id in self._keys:
            if self.verify_identity(key_id, message, sig_hex):
                return key_id
        return None

    def _seed_default_keys(self) -> None:
        """Seed initial key bindings for demo accounts."""
        defaults = [
            ("alice", "alice-key-1", "customer"),
            ("bob", "bob-key-1", "customer"),
            ("carol", "carol-key-1", "customer"),
            ("eve", "eve-key-1", "attacker"),
            ("ops", "ops-key-1", "soc")
        ]
        for user_id, key_id, role in defaults:
            qkd_res = self._simulator.negotiate_session()
            fingerprint = hashlib.sha256(qkd_res.session_key).hexdigest()[:16]
            record = KeyRecord(
                key_id=key_id,
                user_id=user_id,
                role=role,
                qkd_session_id=qkd_res.session_id,
                key_fingerprint=f"QKD-SHA256:{fingerprint}",
                qber=qkd_res.qber,
                status="active",
                dsa_public_key=self._new_identity_key(key_id)
            )
            self._keys[key_id] = record
            self._user_to_keys.setdefault(user_id, []).append(key_id)

    def provision_key_pair(
        self,
        user_id: str,
        role: str = "customer",
        custom_key_id: Optional[str] = None
    ) -> KeyRecord:
        """
        Execute a simulated QKD ceremony (BB84) and provision a new QDS key binding.
        """
        key_id = custom_key_id or f"{user_id}-qds-{uuid.uuid4().hex[:8]}"
        qkd_res = self._simulator.negotiate_session()
        fingerprint = hashlib.sha256(qkd_res.session_key).hexdigest()[:16]

        record = KeyRecord(
            key_id=key_id,
            user_id=user_id,
            role=role,
            qkd_session_id=qkd_res.session_id,
            key_fingerprint=f"QKD-SHA256:{fingerprint}",
            qber=qkd_res.qber,
            status="active",
            dsa_public_key=self._new_identity_key(key_id)
        )
        self._keys[key_id] = record
        self._user_to_keys.setdefault(user_id, []).append(key_id)
        return record

    def validate_key_binding(self, key_id: str, claimed_user: str) -> bool:
        """
        Verify if a given key_id is registered and bound to the claimed user.
        """
        if key_id not in self._keys:
            return False
        return self._keys[key_id].user_id == claimed_user and self._keys[key_id].status == "active"

    def get_key(self, key_id: str) -> Optional[KeyRecord]:
        return self._keys.get(key_id)

    def list_keys(self) -> List[KeyRecord]:
        return list(self._keys.values())


# Global singleton registry
GLOBAL_KEY_REGISTRY = QuantumKeyRegistry()
