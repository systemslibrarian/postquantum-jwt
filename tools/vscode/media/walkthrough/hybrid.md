# How the hybrid is built

The **Hybrid construction** view walks the three steps that turn claims into an encrypted token:

1. **Sign — ML-DSA-65.** The issuer signs the claims, producing a 3-segment signed JWT.
2. **Encapsulate — X-Wing.** A hybrid KEM (X25519 **+** ML-KEM-768) produces a shared secret and a 1120-byte `kem_ct`. The X-Wing combiner binds both halves:

   `ss = SHA3-256( ss_ML-KEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519 ‖ label )`

3. **Encrypt — AES-256-GCM.** The shared secret is the content-encryption key; the whole signed JWT is the plaintext and the header is the AAD.

**Hybrid** matters: an attacker must break *both* X25519 and ML-KEM-768 to recover the key — so the token stays safe even if one is broken later.
