# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Generate a self-consistent CCF-profile "capsule".

A capsule bundles a signed statement, a CCF-profile receipt, the resulting
transparent statement, and the two public keys required to validate them:

* ``statement.cose``            - the signed statement (COSE_Sign1).
* ``transparent-statement.cose``- the signed statement with the receipt embedded
                                  at header label 394.
* ``receipt.cose``              - a CCF-profile receipt (SCITT VDS = 2).
* ``signing-identity.pub``      - public key that validates ``statement.cose``.
* ``log-key.pub``               - service (log) public key that validates the
                                  receipt / transparent statement.

The payload is taken from the ``valid-es256`` scitt-cose test vector and re-signed
with a throwaway test CA, exactly like the integration tests. The receipt is
synthesised offline over a single-leaf Merkle tree, so a complete, spec-compliant
capsule can be produced without a running ledger. The committed live-ledger
capsule is produced by ``test/test_ccf_profile_receipts.py`` and validated by
``test/test_ccf_profile_capsule.py``. This generator is also exercised there to
prove that a fresh offline capsule with different keys remains valid.
"""

import argparse
import hashlib
from dataclasses import dataclass
from pathlib import Path

import cbor2
from ccf.cose import key_fingerprint_from_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from pyscitt import crypto
from pyscitt.cli.validate import strip_uhdr

from .x5chain_certificate_authority import X5ChainCertificateAuthority

# COSE / CWT / CCF header labels used to hand-roll the receipt.
COSE_ALG = 1
COSE_KID = 4
COSE_ALG_ES256 = -7
CWT_CLAIMS = 15
CWT_ISS = 1
CWT_IAT = 6
COSE_HEADER_PARAM_VDS = 395
VDS_CCF = 2
CCF_PROOF = 396
CCF_INCLUSION_PROOFS = -1
CCF_PROOF_LEAF = 1
CCF_PROOF_PATH = 2

# Fixed, arbitrary registration coordinates and time for the sample.
SAMPLE_VIEW = 2
SAMPLE_SEQNO = 15
SAMPLE_IAT = 1700000000

DEFAULT_PAYLOAD_VECTOR = (
    Path(__file__).resolve().parents[1]
    / "test_vectors"
    / "scitt-cose"
    / "v1"
    / "valid-es256"
    / "statement.cose"
)


@dataclass
class Capsule:
    statement: bytes
    transparent_statement: bytes
    receipt: bytes
    signing_identity_pub: str
    log_key_pub: str


def _p1363_signature(private_key: ec.EllipticCurvePrivateKey, tbs: bytes) -> bytes:
    """ECDSA-sign ``tbs`` and return the raw P1363 (r || s) encoding COSE expects."""
    r, s = decode_dss_signature(private_key.sign(tbs, ec.ECDSA(hashes.SHA256())))
    size = (private_key.curve.key_size + 7) // 8
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def synthesize_receipt(
    service_private_pem: str,
    service_public_pem: str,
    signed_statement: bytes,
    issuer: str,
    view: int = SAMPLE_VIEW,
    seqno: int = SAMPLE_SEQNO,
    iat: int = SAMPLE_IAT,
) -> bytes:
    """Build a CCF-profile receipt committing to ``signed_statement``.

    The tree has a single leaf, so its accumulator (Merkle root) is just the leaf
    hash and the inclusion-proof path is empty. The root is signed as the detached
    payload of a COSE_Sign1, which is what ``ccf.cose.verify_receipt`` checks.
    """
    claim_digest = hashlib.sha256(signed_statement).digest()
    internal_hash = bytes(32)
    internal_data = f"ce:{view}.{seqno}:{claim_digest.hex()}"
    leaf = [internal_hash, internal_data, claim_digest]
    accumulator = hashlib.sha256(
        leaf[0] + hashlib.sha256(leaf[1].encode()).digest() + leaf[2]
    ).digest()
    inclusion_proof = cbor2.dumps({CCF_PROOF_LEAF: leaf, CCF_PROOF_PATH: []})

    protected = {
        COSE_ALG: COSE_ALG_ES256,
        COSE_KID: key_fingerprint_from_key(service_public_pem).encode(),
        CWT_CLAIMS: {CWT_ISS: issuer, CWT_IAT: iat},
        COSE_HEADER_PARAM_VDS: VDS_CCF,
        "ccf.v1": {"txid": f"{view}.{seqno}"},
    }
    protected_bstr = cbor2.dumps(protected)
    tbs = cbor2.dumps(["Signature1", protected_bstr, b"", accumulator])

    private_key = load_pem_private_key(service_private_pem.encode(), password=None)
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)
    signature = _p1363_signature(private_key, tbs)

    unprotected = {CCF_PROOF: {CCF_INCLUSION_PROOFS: [inclusion_proof]}}
    return cbor2.dumps(
        cbor2.CBORTag(18, [protected_bstr, unprotected, None, signature])
    )


def generate_capsule(payload_vector: Path = DEFAULT_PAYLOAD_VECTOR) -> Capsule:
    """Produce a fresh, self-consistent CCF-profile capsule."""
    header, payload = crypto.parse_cose_sign1(payload_vector.read_bytes())

    cert_authority = X5ChainCertificateAuthority(kty="ec")
    identity = cert_authority.create_identity(
        alg="ES256", kty="ec", ec_curve="P-256", add_eku="2.999"
    )
    signing_identity_pub = crypto.get_cert_public_key(identity.x5c[0])

    # The verifier recomputes the signed statement as strip_uhdr(transparent
    # statement), so canonicalise the statement through the same round-trip first
    # and let the receipt commit to exactly those bytes.
    statement = strip_uhdr(
        crypto.sign_statement(identity, payload, content_type=header["cty"], cwt=True)
    )

    service_private_pem, log_key_pub = crypto.generate_keypair(
        kty="ec", ec_curve="P-256"
    )
    receipt = synthesize_receipt(
        service_private_pem, log_key_pub, statement, identity.issuer
    )

    outer = cbor2.loads(statement)
    outer.value[1][crypto.SCITTReceipts.identifier] = [receipt]
    transparent_statement = cbor2.dumps(outer)

    return Capsule(
        statement=statement,
        transparent_statement=transparent_statement,
        receipt=receipt,
        signing_identity_pub=signing_identity_pub,
        log_key_pub=log_key_pub,
    )


def write_capsule(output_dir: Path, capsule: Capsule) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "statement.cose").write_bytes(capsule.statement)
    (output_dir / "transparent-statement.cose").write_bytes(
        capsule.transparent_statement
    )
    (output_dir / "receipt.cose").write_bytes(capsule.receipt)
    (output_dir / "signing-identity.pub").write_text(capsule.signing_identity_pub)
    (output_dir / "log-key.pub").write_text(capsule.log_key_pub)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a self-consistent CCF-profile receipt capsule."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory to write the generated capsule files to.",
    )
    args = parser.parse_args()
    write_capsule(args.output_dir, generate_capsule())
