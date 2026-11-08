# qsignify wire format (v1)

`qsignify` keeps the on-disk shape of OpenBSD `signify(1)` — a base64 payload
behind an `untrusted comment:` line — but the payload is a **hybrid
signature** that layers a post-quantum ML-DSA signature with a classic
Ed25519 signature. A hybrid signature verifies only if **both** component
signatures verify over the exact same message bytes.

Two algorithm tags are compared by the parser, mirroring signify's
`memcmp(buf, "Ed", 2)` check. The first byte is always `Q`, the second
selects the ML-DSA parameter set:

| tag | Ed25519 | ML-DSA | NIST category | ML-DSA pub | ML-DSA sig |
|-----|---------|--------|---------------|-----------:|-----------:|
| `Q2`| yes     | ML-DSA-44 (Dilithium2) | 2 | 1312 | 2420 |
| `Q3`| yes     | ML-DSA-65 (Dilithium3) | 3 | 1952 | 3309 |
| `Q5`| yes     | ML-DSA-87 (Dilithium5) | 5 | 2592 | 4627 |

All integers are big-endian. `keynum` is 8 random bytes used to bind a
signature to the public key it was produced for (identical to signify).

## Public key file

```
untrusted comment: <name> public key
base64( Q<p> || keynum[8] || ed25519_pub[32] || mldsa_pub[PKLEN] )
```

## Secret key file

Unlike signify's bcrypt-encrypted secret key, v1 stores the two PKCS#8
private keys directly so the reference implementation can hand them to a
backend. This is a **prototype format**; the layout is versioned by the
leading tag and is expected to gain passphrase encryption later.

```
untrusted comment: <name> secret key
base64( Q<p> || keynum[8] || u16 ed_pkcs8_len || ed_pkcs8_der
                              || u16 mldsa_pkcs8_len || mldsa_pkcs8_der )
```

## Signature file

```
untrusted comment: verify with <name>.pub
base64( Q<p> || keynum[8] || ed25519_sig[64] || mldsa_sig[SIGLEN] )
```

There is no second "global" signature (that is a minisign feature, not
signify). The Ed25519 and ML-DSA signatures are both computed over the raw
message with the respective scheme's native pre-hashing rules (Ed25519 =
PureEdDSA, ML-DSA = FIPS 204 `ML-DSA.Sign`).

## Verification rule

```
accept  iff  keynum(pub) == keynum(sig)  AND
             pkalg(pub)  == pkalg(sig)   AND
             Ed25519.Verify(ed_pub, msg, ed_sig)  AND
             ML-DSA.Verify(mldsa_pub, msg, mldsa_sig)
```

Because ML-DSA is a NIST-standardized algorithm, a verifier built on any
FIPS 204 implementation (OpenSSL 3.5, liboqs `dilithium*`, BouncyCastle
`MLDSASigner`) interoperates as long as the raw key/signature bytes are
reassembled from the file format above.

## Interop notes

* **liboqs** calls ML-DSA-44/65/87 `Dilithium2/3/5` and exposes raw
  `OQS_SIG` public keys and signatures — byte-identical to the values here.
* **OpenSSL 3.5** exposes `ML-DSA-44/65/87` (default provider) and
  `ED25519`. Its DER SPKI/SCPI wrappers are stripped/rebuilt by the
  reference tool; only the raw payloads live in the qsignify files.
* **BouncyCastle** (1.79+) exposes
  `org.bouncycastle.pqc.crypto.mldsa.MLDSASigner` and
  `org.bouncycastle.crypto.params.Ed25519PublicKeyParameters`. See
  `java/` for a verifier that consumes qsignify files.
