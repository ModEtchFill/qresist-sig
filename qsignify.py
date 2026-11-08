#!/usr/bin/env python3
# qsignify - openbsd-signify-shaped hybrid signatures: Ed25519 + ML-DSA (FIPS 204)
#
# Reference implementation. Requires the `openssl` CLI (3.5+) for the
# ML-DSA / Ed25519 primitives. See SPEC.md for the wire format.
#
# SPDX-License-Identifier: ISC

import argparse
import base64
import os
import struct
import subprocess
import sys
import tempfile

COMMENTHDR = b"untrusted comment: "
VERIFYWITH = "verify with "

# tag -> (backend algo name, raw pubkey len, raw sig len)
SUITES = {
    "Q2": ("ML-DSA-44", 1312, 2420),
    "Q3": ("ML-DSA-65", 1952, 3309),
    "Q5": ("ML-DSA-87", 2592, 4627),
}
DEFAULT_SUITE = "Q2"

ED25519_PUBLEN = 32
ED25519_SIGLEN = 64
KEYNUMLEN = 8

# DER OIDs (full OID TLV) used to rebuild SubjectPublicKeyInfo wrappers.
ED25519_OID = bytes.fromhex("06032b6570")
MLDSA_OID = {
    "Q2": bytes.fromhex("0609608648016503040311"),
    "Q3": bytes.fromhex("0609608648016503040312"),
    "Q5": bytes.fromhex("0609608648016503040313"),
}


class QSignifyError(Exception):
    pass


# --------------------------------------------------------------------------
# tiny DER helper
# --------------------------------------------------------------------------
def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, val):
    return bytes([tag]) + _der_len(len(val)) + val


def spki_from_raw(raw, oid):
    """Build a SubjectPublicKeyInfo DER from a raw public key + OID TLV."""
    algid = _tlv(0x30, oid)
    bitstr = _tlv(0x03, b"\x00" + raw)
    return _tlv(0x30, algid + bitstr)


# --------------------------------------------------------------------------
# openssl backend
# --------------------------------------------------------------------------
def _run(args, **kw):
    return subprocess.run(
        ["openssl", *args], capture_output=True, check=True, **kw
    )


def openssl_genpkey(algo):
    """Return the PKCS#8 DER of a fresh private key."""
    return _run(["genpkey", "-algorithm", algo, "-outform", "DER"]).stdout


def openssl_pubkey_raw(sk_der, rawlen):
    """Extract the raw public key from a PKCS#8 private key DER."""
    spki = _run(
        ["pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
        input=sk_der,
    ).stdout
    if len(spki) < rawlen:
        raise QSignifyError("bad public key encoding")
    return spki[-rawlen:]


def openssl_sign(sk_der, msg):
    with tempfile.NamedTemporaryFile() as kf, tempfile.NamedTemporaryFile() as mf:
        kf.write(sk_der)
        kf.flush()
        mf.write(msg)
        mf.flush()
        return _run(
            [
                "pkeyutl", "-sign",
                "-inkey", kf.name, "-keyform", "DER",
                "-rawin", "-in", mf.name,
            ]
        ).stdout


def openssl_verify(pub_raw, oid, msg, sig):
    spki = spki_from_raw(pub_raw, oid)
    with tempfile.NamedTemporaryFile() as kf, \
            tempfile.NamedTemporaryFile() as mf, \
            tempfile.NamedTemporaryFile() as sf:
        kf.write(spki)
        kf.flush()
        mf.write(msg)
        mf.flush()
        sf.write(sig)
        sf.flush()
        p = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify",
                "-pubin", "-inkey", kf.name, "-keyform", "DER",
                "-rawin", "-in", mf.name, "-sigfile", sf.name,
            ],
            capture_output=True,
        )
        return p.returncode == 0


# --------------------------------------------------------------------------
# file helpers
# --------------------------------------------------------------------------
def b64e(data):
    return base64.b64encode(data).decode("ascii")


def b64d(text):
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise QSignifyError("invalid base64 payload") from exc


def write_b64_file(path, comment, payload, mode):
    blob = COMMENTHDR + comment.encode() + b"\n" + b64e(payload).encode() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    try:
        os.write(fd, blob)
    finally:
        os.close(fd)


def read_b64_file(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    nl = raw.find(b"\n")
    if nl < 0 or not raw.startswith(COMMENTHDR):
        raise QSignifyError(f"invalid comment in {path}")
    comment = raw[len(COMMENTHDR):nl].decode("utf-8", "replace")
    rest = raw[nl + 1:]
    nl2 = rest.find(b"\n")
    line = rest if nl2 < 0 else rest[:nl2]
    return comment, b64d(line.decode("ascii").strip())


def read_message(path):
    if path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as fh:
        return fh.read()


def keyname_basename(secpath):
    base = os.path.basename(secpath)
    if base.endswith(".sec") and len(base) > 4:
        return base[:-4]
    return None


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def cmd_generate(args):
    tag = args.alg
    algo, publen, _ = SUITES[tag]
    if args.comment is None:
        args.comment = "qsignify"

    ed_sk = openssl_genpkey("ED25519")
    pq_sk = openssl_genpkey(algo)
    ed_pub = openssl_pubkey_raw(ed_sk, ED25519_PUBLEN)
    pq_pub = openssl_pubkey_raw(pq_sk, publen)
    keynum = os.urandom(KEYNUMLEN)

    pub = tag.encode() + keynum + ed_pub + pq_pub
    sec = (
        tag.encode()
        + keynum
        + struct.pack(">H", len(ed_sk)) + ed_sk
        + struct.pack(">H", len(pq_sk)) + pq_sk
    )

    write_b64_file(args.pubkey, f"{args.comment} public key", pub, 0o666)
    write_b64_file(args.seckey, f"{args.comment} secret key", sec, 0o600)
    print(f"generated {tag} keypair")


def _parse_seckey(sec):
    tag = sec[:2].decode("ascii", "replace")
    if tag not in SUITES:
        raise QSignifyError(f"unsupported algorithm tag {tag!r}")
    keynum = sec[2:2 + KEYNUMLEN]
    off = 2 + KEYNUMLEN
    (ed_len,) = struct.unpack_from(">H", sec, off)
    off += 2
    ed_sk = sec[off:off + ed_len]
    off += ed_len
    (pq_len,) = struct.unpack_from(">H", sec, off)
    off += 2
    pq_sk = sec[off:off + pq_len]
    if len(pq_sk) != pq_len:
        raise QSignifyError("truncated secret key")
    return tag, keynum, ed_sk, pq_sk


def _parse_pubkey(pub):
    tag = pub[:2].decode("ascii", "replace")
    if tag not in SUITES:
        raise QSignifyError(f"unsupported algorithm tag {tag!r}")
    _, publen, _ = SUITES[tag]
    keynum = pub[2:2 + KEYNUMLEN]
    off = 2 + KEYNUMLEN
    ed_pub = pub[off:off + ED25519_PUBLEN]
    off += ED25519_PUBLEN
    pq_pub = pub[off:off + publen]
    if len(pq_pub) != publen:
        raise QSignifyError("truncated public key")
    return tag, keynum, ed_pub, pq_pub


def cmd_sign(args):
    _, sec = read_b64_file(args.seckey)
    tag, keynum, ed_sk, pq_sk = _parse_seckey(sec)
    algo = SUITES[tag][0]
    msg = read_message(args.message)

    ed_sig = openssl_sign(ed_sk, msg)
    pq_sig = openssl_sign(pq_sk, msg)
    if len(ed_sig) != ED25519_SIGLEN:
        raise QSignifyError("unexpected Ed25519 signature length from backend")

    name = keyname_basename(args.seckey)
    if name:
        comment = VERIFYWITH + name + ".pub"
    else:
        comment = "signature from " + os.path.basename(args.seckey)

    payload = tag.encode() + keynum + ed_sig + pq_sig
    write_b64_file(args.sigfile, comment, payload, 0o666)
    print(f"signature written to {args.sigfile}")


def _parse_sig(sig):
    tag = sig[:2].decode("ascii", "replace")
    if tag not in SUITES:
        raise QSignifyError(f"unsupported algorithm tag {tag!r}")
    keynum = sig[2:2 + KEYNUMLEN]
    off = 2 + KEYNUMLEN
    ed_sig = sig[off:off + ED25519_SIGLEN]
    off += ED25519_SIGLEN
    pq_sig = sig[off:]
    return tag, keynum, ed_sig, pq_sig


def cmd_verify(args):
    _, pub = read_b64_file(args.pubkey)
    _, sig = read_b64_file(args.sigfile)
    tag, keynum, ed_pub, pq_pub = _parse_pubkey(pub)
    sig_tag, sig_keynum, ed_sig, pq_sig = _parse_sig(sig)

    if tag != sig_tag:
        raise QSignifyError("verification failed: algorithm mismatch")
    if keynum != sig_keynum:
        raise QSignifyError("verification failed: checked against wrong key")
    if len(pq_sig) != SUITES[tag][2]:
        raise QSignifyError("verification failed: malformed signature length")

    msg = read_message(args.message)
    if not openssl_verify(ed_pub, ED25519_OID, msg, ed_sig):
        raise QSignifyError("signature verification failed (Ed25519)")
    if not openssl_verify(pq_pub, MLDSA_OID[tag], msg, pq_sig):
        raise QSignifyError("signature verification failed (ML-DSA)")
    if not args.quiet:
        print("Signature Verified")


# --------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="qsignify",
        description="signify-style hybrid Ed25519 + ML-DSA signatures",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-G", "--generate", action="store_true", help="generate a keypair")
    g.add_argument("-S", "--sign", action="store_true", help="sign a message")
    g.add_argument("-V", "--verify", action="store_true", help="verify a signature")

    p.add_argument("-p", "--pubkey", help="public key file")
    p.add_argument("-s", "--seckey", help="secret key file")
    p.add_argument("-m", "--message", help="message file ('-' for stdin)")
    p.add_argument("-x", "--sigfile", help="signature file")
    p.add_argument("-c", "--comment", help="key comment")
    p.add_argument("-a", "--alg", choices=sorted(SUITES), default=DEFAULT_SUITE,
                   help="hybrid suite (default: %(default)s)")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress output")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.generate:
            if not args.pubkey or not args.seckey:
                raise QSignifyError("-G requires -p and -s")
            cmd_generate(args)
        elif args.sign:
            if not args.seckey or not args.message:
                raise QSignifyError("-S requires -s and -m")
            if not args.sigfile:
                if args.message == "-":
                    raise QSignifyError("-S with stdin requires -x")
                args.sigfile = args.message + ".sig"
            cmd_sign(args)
        elif args.verify:
            if not args.pubkey or not args.message or not args.sigfile:
                raise QSignifyError("-V requires -p, -m and -x")
            cmd_verify(args)
    except (QSignifyError, subprocess.CalledProcessError) as exc:
        print(f"qsignify: {exc}", file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError):
            print(exc.stderr.decode(errors="replace"), file=sys.stderr, end="")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
