# Transparency Trust Lists

## Motivation

Transparency receipts are only useful at scale if a relying party can decide quickly and reliably whether the Transparency Service (TS) that issued them is one it should trust. Today that requires reaching out to the TS, establishing its authenticity, and fetching its set of trusted signing keys. The key set can be cached, but only effectively in long-lived contexts.

A Transparency Trust List (TTL) simplifies this: it is a signed, portable artifact naming the TS instances a relying party trusts and their respective trusted signing keys, so receipts can be validated offline and deterministically. TTLs unlock portable trust decisions across relying parties without online lookups, and can be distributed through any channel, including out-of-band.

## Refresh Frequency

A TTL should be refreshed when:

1. A TS instance is added to or removed from the list of trusted issuers.
2. The signing keys of a trusted TS instance are rotated or revoked.

## Schema

### Payload

```cddl
; Definitions imported from RFC 9052 (COSE).
label = int / tstr
values = any

COSE_Key = {
    1 => tstr / int,          ; kty
    ? 2 => bstr,              ; kid
    ? 3 => tstr / int,        ; alg
    ? 4 => [+ (tstr / int) ], ; key_ops
    ? 5 => bstr,              ; Base IV
    * label => values
}

COSE_KeySet = [+ COSE_Key]

issuer = tstr

; Map of issuers to their COSE Key Sets.
; Must contain at least one issuer entry.
TransparencyTrustListPayload = {
    + issuer => COSE_KeySet
}
```

`COSE_KeySet` is used here so that the trusted key material for each
issuer is in exactly the same shape that a Transparency Service exposes
under its `/.well-known/scitt-keys` resource, defined in
[Section 2.1 of draft-ietf-scitt-scrapi](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-10#section-2.1)
("Transparency Service Keys"). That endpoint returns a COSE Key Set
(per Section 7 of [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html))
serialized as `application/cbor`, and individual keys are resolvable by
`kid` under
[Section 2.2 of the same draft](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-10#section-2.2)
(`/.well-known/scitt-keys/{kid_value}`). Reusing the same encoding lets a
TTL be assembled from, and verified against, the live SCRAPI key
resources without any transformation.

### Envelope

The Transparency Trust List is a signed `COSE_Sign1` message whose payload is the `TransparencyTrustListPayload` defined above. The protected header carries the content type, a CWT Claims Set ([RFC 9597](https://www.rfc-editor.org/rfc/rfc9597.html)) identifying the TTL issuer and subject, and optionally the signing algorithm, key identifier, and an X.509 certificate chain ([RFC 9360](https://www.rfc-editor.org/rfc/rfc9360.html)).

```cddl
; A signed COSE_Sign1 (Section 4.2 of RFC 9052) carrying the TransparencyTrustListPayload.

TTL_content_type = "application/vnd.transparency-trust-list+cose"

; CWT Claims Set carried in a COSE header per RFC 9597
; ("CBOR Web Token (CWT) Claims in COSE Headers"), using the
; CWT claims registered in RFC 8392 Section 3.1.
; iss (1) and sub (2) are mandatory for a Transparency Trust List;
; all other CWT claims are optional.
TTL_CWT_Claims = {
    1 => tstr,                ; iss (issuer)
    2 => tstr,                ; sub (subject)
    * label => values
}

TTL_Protected_Header_Map = {
    3  => TTL_content_type,     ; content type
    15 => TTL_CWT_Claims,       ; CWT Claims (RFC 9597)
    ? 1  => int / tstr,         ; algorithm identifier
    ? 4  => bstr,               ; key identifier
    ? 33 => bstr / [ 2* bstr ], ; x5chain - X.509 certificate chain (RFC 9360)
    * label => values
}

TTL_Unprotected_Header_Map = {
    * label => values
}

TransparencyTrustList = [
    protected   : bstr .cbor TTL_Protected_Header_Map,
    unprotected : TTL_Unprotected_Header_Map,
    payload     : bstr .cbor TransparencyTrustListPayload,
    signature   : bstr
]

TransparencyTrustList_Tagged = #6.18(TransparencyTrustList)
```

## Example Trust List Payload

```edn
{ / TransparencyTrustListPayload: map of issuer => COSE_KeySet /
  "esrp-cts-dev.confidential-ledger.azure.com"
      / issuer identifier (TS instance URL) /:
  [ / COSE_KeySet: one or more COSE_Key entries /
    {
      1  / kty /: 2          / EC2 (Elliptic Curve, x and y coords) /,
      2  / kid /: h'46cfd71010b47ff5aed2f9df227c64dd1c9d41ff176b361418485128388e1743'
                  / key identifier (raw bytes of the hex kid above) /,
      3  / alg /: -35        / ES384 (ECDSA with SHA-384) /,
      -1 / crv /: 2          / P-384 (NIST secp384r1) /,
      -2 / x   /: h'6e1cebcb5d000438060e641783dde6144c204922be8a9ade01a80943f35daffb0902a7376e826192e61885c66d4c2e85'
                  / x coordinate of the public key (48 bytes) /,
      -3 / y   /: h'd4a80463c41c64aef148aac86f4b984ae9eb23ebb0c5f81a19cd0062edb2dd249285396905115428a825d3e28c8c290b'
                  / y coordinate of the public key (48 bytes) /
    },
    {
      1  / kty /: 2          / EC2 (Elliptic Curve, x and y coords) /,
      2  / kid /: h'cd73d37679fb39218c7e12d24cb443504d8535e783714d5529ebac335e897e85'
                  / key identifier (raw bytes of the hex kid above) /,
      3  / alg /: -35        / ES384 (ECDSA with SHA-384) /,
      -1 / crv /: 2          / P-384 (NIST secp384r1) /,
      -2 / x   /: h'f256e75dd2f189e40730e16f7f14034d74cef15636fa5ac93b660c2802867fa03d90c35769e478a1910337a5c5e69fa1'
                  / x coordinate of the public key (48 bytes) /,
      -3 / y   /: h'ba8270adbe3352e0187bd096c978552797b615af8440e8a16474dba843ed539fff931ab4d0756f0a1c626795d9d29e3b'
                  / y coordinate of the public key (48 bytes) /
    }
  ],
  "esrp-cts-ppe.confidential-ledger.azure.com"
      / issuer identifier (TS instance URL) /:
  [ / COSE_KeySet: one or more COSE_Key entries /
    {
      1  / kty /: 2          / EC2 (Elliptic Curve, x and y coords) /,
      2  / kid /: h'b3a9d84ea840bf12c76f9a849f5427ae88984d458b0f3b282cb297957c96331e'
                  / key identifier (raw bytes of the hex kid above) /,
      3  / alg /: -35        / ES384 (ECDSA with SHA-384) /,
      -1 / crv /: 2          / P-384 (NIST secp384r1) /,
      -2 / x   /: h'6aca17451eac82b58831b617bc50ac02731500592ba6c3724efe49b6ad4d2b72527a74d26ce11424cb2ee7c267d42831'
                  / x coordinate of the public key (48 bytes) /,
      -3 / y   /: h'237c8db963d4b510b284957fe34dd807f621146526a0152f672ced51c10b9c4b68699e58293edf3402d878ea6bc87866'
                  / y coordinate of the public key (48 bytes) /
    },
    {
      1  / kty /: 2          / EC2 (Elliptic Curve, x and y coords) /,
      2  / kid /: h'8e6792c498f1a9c6007fef852baff1a3c141a10fea06bee6ce0cfb7e8bec37d5'
                  / key identifier (raw bytes of the hex kid above) /,
      3  / alg /: -35        / ES384 (ECDSA with SHA-384) /,
      -1 / crv /: 2          / P-384 (NIST secp384r1) /,
      -2 / x   /: h'23a2cb3bc3872c08e5af362748576d216e3c6b801eb740d97989661989e7e4cbd25f786700615172a6200dfc03aa65b9'
                  / x coordinate of the public key (48 bytes) /,
      -3 / y   /: h'06924b9ba39bffc16e8f38b03e2681ee00c1e8b4c5b709991ff13b3df294d7b33e7ea22c1bde5e56773ca807ad22c072'
                  / y coordinate of the public key (48 bytes) /
    }
  ]
}
```
