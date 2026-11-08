# qresist-sig

**DO NOT USE!!!! UNPROTECTED SECRET KEY**

`signify(1)`-shaped signatures that **layer a post-quantum ML-DSA signature
with classic Ed25519**. A signature is accepted only if *both* component
signatures verify over the message, and the signature is bound to a specific
keypair with an 8-byte `keynum` — exactly like OpenBSD signify.

* [`SPEC.md`](SPEC.md) — the qsignify wire format and interop notes.
* [`qsignify.py`](qsignify.py) — runnable Python reference (stdlib + `openssl`).
* [`src/qsignify.c`](src/qsignify.c) — native reference: **liboqs** ML-DSA +
  OpenSSL Ed25519.
* [`java/QSignifyVerify.java`](java/QSignifyVerify.java) — BouncyCastle verifier.
* [`tests/run.sh`](tests/run.sh) — round-trip, negative, and cross-implementation tests.

## Supported suites

| tag | Ed25519 | ML-DSA | public key payload | signature payload |
|-----|---------|--------|-------------------:|------------------:|
| `Q2`| yes | ML-DSA-44 (Dilithium2) | 1354 B | 2494 B |
| `Q3`| yes | ML-DSA-65 (Dilithium3) | 1994 B | 3383 B |
| `Q5`| yes | ML-DSA-87 (Dilithium5) | 2634 B | 4701 B |

Public keys and signatures are the shared wire format; the two backends
produce byte-compatible `.pub`/`.sig` files and can verify each other. The
`.sec` layout is backend-specific (Python stores OpenSSL PKCS#8 DERs; the
native tool stores a raw Ed25519 seed + the liboqs ML-DSA secret key).

## Build

```sh
# 1. liboqs into third_party/liboqs (no root needed)
./scripts/build-liboqs.sh          # LIBOQS_VERSION=0.16.0 by default

# 2. native qsignify
make -C src

# 3. optional: BouncyCastle jar for the interop test
./scripts/get-bcprov.sh            # writes bcprov-jdk18on-1.79.jar
```

## Usage

Python reference and native binary accept the same flags:

```sh
qsignify -G -a Q2 -p demo.pub -s demo.sec -c demo   # generate
qsignify -S -s demo.sec -m demo.msg                 # sign -> demo.msg.sig
qsignify -V -p demo.pub -m demo.msg -x demo.msg.sig # verify
# -> Signature Verified
```

Files keep signify's shape:

```
$ cat demo.pub
untrusted comment: demo public key
JDLBAAAAAAAA...base64...
```

## Test

```sh
BCPROV_JAR=$PWD/bcprov-jdk18on-1.79.jar ./tests/run.sh
```

The suite currently passes **30/30**:

* python round trip + tamper + wrong-key rejection for `Q2`/`Q3`/`Q5`
* native (liboqs) round trip + tamper + wrong-key rejection
* python ⇄ native cross-verification
* BouncyCastle verifies both python- and native-produced signatures

## Interoperability notes

OpenSSL's `ML-DSA-44/65/87`, liboqs' `ML-DSA-44/65/87` (formerly
`Dilithium2/3/5`) and BouncyCastle's `MLDSASigner` all implement FIPS 204, so
they emit and accept identical raw keys and signatures. qsignify only adds the
signify-style container (comment line + base64 + `keynum` binding), which is
why the same `.pub`/`.sig` files verify under all three implementations.
