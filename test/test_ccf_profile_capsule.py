# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import hashlib
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from pyscitt import crypto
from pyscitt.cli.validate import strip_uhdr, validate_transparent_statement
from pyscitt.verify import (
    StaticTrustStore,
    verify_cose_sign1,
    verify_transparent_statement,
)

from .infra.generate_ccf_profile_capsule import generate_capsule

# A self-consistent CCF-profile capsule generated offline by
# test/infra/generate_ccf_profile_capsule.py: the valid-es256 payload re-signed
# with a throwaway test CA, plus a synthesised CCF-profile receipt and the two
# public keys required to validate the bundle.
CAPSULE_DIR = Path(__file__).parent / "test_vectors" / "ccf-profile-capsule"
STATEMENT = CAPSULE_DIR / "statement.cose"
RECEIPT = CAPSULE_DIR / "receipt.cose"
TRANSPARENT_STATEMENT = CAPSULE_DIR / "transparent-statement.cose"
SIGNING_IDENTITY = CAPSULE_DIR / "signing-identity.pub"
LOG_KEY = CAPSULE_DIR / "log-key.pub"

ISSUER = "did:x509:0:sha256:nwtobwWRyGtCzjHPOUK91nTeZa5NZt2K32AnInyQ4Jo::eku:2.999"


def test_ccf_profile_capsule_is_pinned():
    expected = {
        "statement.cose": "3421f4881fad23930cbcb41e16571b66ebc5c7eaedc38624bac6487d879c579b",
        "receipt.cose": "ee1e68f83ae1ee8e496bb11c15e849ada92039b6adc5fb98aacf273ce3d4eba1",
        "transparent-statement.cose": "80833fc16d59347169b7769a81050d2e5a0338d3c6fbde851733215c6fe297c6",
        "signing-identity.pub": "36625b3d91df2f3aa2eb3f54cdf426f6e21f417f91f7947daa12d671c2f45c4b",
        "log-key.pub": "dde9a77dbcaa5b5ec2e2df836f1dfd69c6e6b3b2f784ffe93bf4a1db901ffde1",
    }
    assert {
        name: hashlib.sha256((CAPSULE_DIR / name).read_bytes()).hexdigest()
        for name in expected
    } == expected


def test_ccf_profile_capsule_statement_signature():
    # The signed statement verifies against the exported signing identity key.
    verify_cose_sign1(STATEMENT.read_bytes(), SIGNING_IDENTITY.read_text())


def test_ccf_profile_capsule_transparent_statement():
    transparent_statement = TRANSPARENT_STATEMENT.read_bytes()
    signed_statement = strip_uhdr(transparent_statement)

    # The receipt is embedded as a bstr at header label 394 and stripping it
    # recovers exactly the committed signed statement.
    assert cbor2.loads(transparent_statement).value[1] == {
        crypto.SCITTReceipts.identifier: [RECEIPT.read_bytes()]
    }
    assert signed_statement == STATEMENT.read_bytes()

    trust_store = StaticTrustStore(key=load_pem_public_key(LOG_KEY.read_bytes()))
    assert verify_transparent_statement(
        transparent_statement, trust_store, signed_statement
    ) == [
        {
            "iss": ISSUER,
            "iat": 1700000000,
            "sigtxid": "2.15",
            "regtxid": "2.15",
        }
    ]


def test_validate_ccf_profile_capsule(capsys):
    validate_transparent_statement(TRANSPARENT_STATEMENT, service_key=LOG_KEY)
    out = capsys.readouterr().out.strip().splitlines()
    assert out[-1] == f"Statement is transparent: {TRANSPARENT_STATEMENT}"
    assert f"Verified receipt from issuer {ISSUER}" in out[0]


def test_generator_produces_valid_capsule():
    # A freshly generated capsule (new keys, different digests) is equally valid.
    capsule = generate_capsule()

    verify_cose_sign1(capsule.statement, capsule.signing_identity_pub)

    assert strip_uhdr(capsule.transparent_statement) == capsule.statement
    assert cbor2.loads(capsule.transparent_statement).value[1] == {
        crypto.SCITTReceipts.identifier: [capsule.receipt]
    }

    trust_store = StaticTrustStore(
        key=load_pem_public_key(capsule.log_key_pub.encode())
    )
    (details,) = verify_transparent_statement(
        capsule.transparent_statement, trust_store, capsule.statement
    )
    assert details["iss"].startswith("did:x509:0:sha256:")
