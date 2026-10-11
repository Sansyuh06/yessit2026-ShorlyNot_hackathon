from typing import Optional
from shorlynot_skeleton.models import SignatureBundle
from shorlynot_skeleton.qds.protocol import QdsT1Protocol
from shorlynot_skeleton.qkd.key_registry import GLOBAL_KEY_REGISTRY
from shorlynot_skeleton.pqc.identity import identity_message


class ImpersonationAttack:
    """
    Simulates Eve attempting to sign a transfer claiming to be Alice,
    using Eve's private quantum key material while claiming Alice's key_id.
    """

    @staticmethod
    def generate_impersonated_bundle(
        payload_hash: str,
        claimed_key_id: str = "alice-key-1",
        attacker_key_id: str = "eve-key-1",
        qds_protocol: Optional[QdsT1Protocol] = None
    ) -> SignatureBundle:
        protocol = qds_protocol or QdsT1Protocol()
        # Eve signs properly with her own quantum device and key material (attacker_key_id)
        bundle = protocol.sign(
            payload_hash=payload_hash,
            key_id=attacker_key_id,
            n_checks=64,
            L=128
        )
        # Then claims to be Alice by setting bundle.key_id = claimed_key_id
        bundle.key_id = claimed_key_id
        # Eve can only sign with the identity key she actually holds. No self-incriminating label is set:
        # the verifier has to catch her from the signature alone.
        bundle.identity_sig = GLOBAL_KEY_REGISTRY.sign_identity(
            attacker_key_id,
            identity_message(bundle.payload_hash, bundle.nonce, claimed_key_id, bundle.n_checks, bundle.L)
        )
        bundle.measurement_transcript["attack"] = "impersonation"
        return bundle

