# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os
from pathlib import Path

from pyscitt import crypto
from pyscitt.cli.validate import strip_uhdr
from pyscitt.client import Client
from pyscitt.verify import verify_cose_sign1, verify_transparent_statement

# The payload is lifted from the valid-es256 RFC 9942 test vector's signed
# statement. We re-sign that exact payload with a locally generated test CA (as
# the other integration tests do) and register it with the ledger, which yields
# a CCF-profile receipt. The signed statement, transparent statement, receipt
# and signing identity are then exported so the combination can be reused
# elsewhere as a self-consistent capsule.
VALID_ES256_STATEMENT = (
    Path(__file__).parent
    / "test_vectors"
    / "scitt-cose"
    / "v1"
    / "valid-es256"
    / "statement.cose"
)


def _resolve_output_dir(default: Path) -> Path:
    """Pick the artifact output directory, honouring SCITT_OUTPUT_DIR."""
    override = os.environ.get("SCITT_OUTPUT_DIR")
    output_dir = Path(override) if override else default
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def test_produce_ccf_profile_receipt_for_capsule(
    client: Client,
    cert_authority,
    trust_store,
    configure_service,
    tmp_path: Path,
):
    """
    Produce a valid combination of signed statement, transparent statement,
    receipt and signing identity from the valid-es256 vector payload.
    """
    # Reuse the exact payload (and its content type) of the valid-es256 vector,
    # discarding the vector's own signature and protected headers.
    header, payload = crypto.parse_cose_sign1(VALID_ES256_STATEMENT.read_bytes())
    content_type = header["cty"]

    # Sign that payload with a fresh identity issued by the test CA, and open
    # the registration policy so the ledger accepts this issuer.
    identity = cert_authority.create_identity(
        alg="ES256", kty="ec", ec_curve="P-256", add_eku="2.999"
    )
    configure_service(
        {
            "policy": {
                "policyScript": f'export function apply(phdr) {{ return phdr.cwt.iss === "{identity.issuer}"; }}'
            }
        }
    )
    signed_statement = crypto.sign_statement(
        identity, payload, content_type=content_type, cwt=True
    )

    # Register the signed statement and obtain the CCF-profile receipt, which
    # the ledger embeds into the returned transparent statement.
    transparent_statement = client.submit_signed_statement_and_wait(
        signed_statement
    ).response_bytes
    receipt = crypto.get_last_embedded_receipt_from_cose(transparent_statement)
    assert receipt is not None, "ledger did not embed a receipt"

    # Stripping the unprotected header of the transparent statement must recover
    # exactly the signed statement we submitted.
    assert strip_uhdr(transparent_statement) == signed_statement

    # The signing identity certificate chain, leaf certificate first.
    signing_identity_pem = "".join(identity.x5c)

    # The four artifacts must form a valid, self-consistent combination:
    #  - the statement is signed by the exported signing identity, and
    #  - the receipt is a valid transparency proof over that statement.
    verify_cose_sign1(signed_statement, crypto.get_cert_public_key(identity.x5c[0]))
    verify_transparent_statement(transparent_statement, trust_store, signed_statement)

    output_dir = _resolve_output_dir(tmp_path)
    (output_dir / "statement.cose").write_bytes(signed_statement)
    (output_dir / "transparent-statement.cose").write_bytes(transparent_statement)
    (output_dir / "receipt.cose").write_bytes(receipt)
    (output_dir / "signing-identity.pem").write_text(signing_identity_pem)

    print(f"Wrote CCF-profile receipt capsule to {output_dir}")
