# Signed vs. encrypted

PostQuantum.Jwt produces two compact-serialization forms:

| Form | Segments | Layout | Header `alg` |
| --- | --- | --- | --- |
| **Signed** | 3 | `header.payload.signature` | `ML-DSA-65` |
| **Encrypted** | 5 | `header.kem_ct.iv.ciphertext.tag` | `X-Wing` (+ `enc: A256GCM`) |

The encrypted form is **sign-then-encrypt**: a complete signed token becomes the plaintext of a JWE, so the signature — and who signed it — is confidential too.

The inspector's **Token** tab labels and color-codes every segment, and flags the expected `ML-DSA-65` / `X-Wing` / `A256GCM` identifiers.
