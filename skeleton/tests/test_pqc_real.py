"""Real PQC: ML-KEM-768 (FIPS 203), ML-DSA-44 (FIPS 204), hybrid key, and identity attribution."""
import pytest

from shorlynot_skeleton.pqc.kem_interface import MlKem768Interface
from shorlynot_skeleton.pqc.hybrid import derive_hybrid_key
from shorlynot_skeleton.pqc.identity import identity_message
from shorlynot_skeleton.qkd.key_registry import GLOBAL_KEY_REGISTRY


def test_mlkem_roundtrip_and_sizes():
    pk, sk = MlKem768Interface.keypair()
    ct, ss = MlKem768Interface.encapsulate(pk)
    assert len(pk) == 1184 and len(ct) == 1088 and len(ss) == 32
    assert MlKem768Interface.decapsulate(ct, sk) == ss


def test_mlkem_implicit_rejection_on_tampered_ciphertext():
    pk, sk = MlKem768Interface.keypair()
    ct, ss = MlKem768Interface.encapsulate(pk)
    bad = bytearray(ct)
    bad[10] ^= 1
    assert MlKem768Interface.decapsulate(bytes(bad), sk) != ss


def test_hybrid_key_depends_on_both_inputs():
    k = derive_hybrid_key(b"a" * 32, b"b" * 32)
    assert k != derive_hybrid_key(b"c" * 32, b"b" * 32)
    assert k != derive_hybrid_key(b"a" * 32, b"c" * 32)


def test_identity_signature_verifies_only_under_own_key():
    msg = identity_message("h", "n", "alice-key-1", 64, 128)
    sig = GLOBAL_KEY_REGISTRY.sign_identity("alice-key-1", msg)
    assert GLOBAL_KEY_REGISTRY.verify_identity("alice-key-1", msg, sig)
    assert not GLOBAL_KEY_REGISTRY.verify_identity("eve-key-1", msg, sig)
    assert not GLOBAL_KEY_REGISTRY.verify_identity("alice-key-1", identity_message("h2", "n", "alice-key-1", 64, 128), sig)


def test_identify_signer_attributes_the_real_key():
    msg = identity_message("h", "n", "alice-key-1", 64, 128)
    sig = GLOBAL_KEY_REGISTRY.sign_identity("eve-key-1", msg)
    assert GLOBAL_KEY_REGISTRY.identify_signer(msg, sig) == "eve-key-1"


def _clean_verify_result():
    from shorlynot_skeleton.models import VerifyResult
    return VerifyResult(candidate_accepted=True, mismatch_rate=0.0, mismatches=0, n_checks=64, tau=0.2097)


def _bundle(key_id="alice-key-1", nonce="n-ident-1"):
    from shorlynot_skeleton.models import SignatureBundle
    return SignatureBundle(payload_hash="ab" * 32, key_id=key_id, nonce=nonce, bases=[0] * 128,
                           correction_bits=[[0, 0]] * 64, n_checks=64, L=128)


def test_identity_signature_alone_catches_impersonation_and_attributes_signer():
    from shorlynot_skeleton.detect.classifier import QstdfClassifier
    from shorlynot_skeleton.models import ThreatLabel
    b = _bundle()
    b.identity_sig = GLOBAL_KEY_REGISTRY.sign_identity(
        "eve-key-1", identity_message(b.payload_hash, b.nonce, b.key_id, b.n_checks, b.L))
    res = QstdfClassifier().classify(b, _clean_verify_result(), claimed_signer="alice",
                                     require_identity_sig=True)
    assert res.label == ThreatLabel.IMPERSONATION
    assert res.details["attributed_key"] == "eve-key-1"


def test_unsigned_bundle_is_rejected_even_with_perfect_statistics():
    from shorlynot_skeleton.detect.classifier import QstdfClassifier
    from shorlynot_skeleton.models import ThreatLabel
    res = QstdfClassifier().classify(_bundle(nonce="n-ident-2"), _clean_verify_result(),
                                     claimed_signer="alice", require_identity_sig=True)
    assert res.label == ThreatLabel.FORGERY and res.details.get("unsigned") is True


def test_validly_signed_bundle_passes():
    from shorlynot_skeleton.detect.classifier import QstdfClassifier
    from shorlynot_skeleton.models import ThreatLabel
    b = _bundle(nonce="n-ident-3")
    b.identity_sig = GLOBAL_KEY_REGISTRY.sign_identity(
        "alice-key-1", identity_message(b.payload_hash, b.nonce, b.key_id, b.n_checks, b.L))
    res = QstdfClassifier().classify(b, _clean_verify_result(), claimed_signer="alice",
                                     require_identity_sig=True)
    assert res.label == ThreatLabel.OK
