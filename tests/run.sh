#!/usr/bin/env bash
# End-to-end + interoperability tests for qsignify.
#
#   python reference  (qsignify.py, OpenSSL backend)
#   native reference  (src/qsignify, liboqs + OpenSSL)      [if built]
#   BouncyCastle      (java/QSignifyVerify.java)            [if BCPROV_JAR set]
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

printf 'the quick brown fox\n' > "$tmp/msg"
printf 'the quick brown fix\n' > "$tmp/bad"

native=""
[[ -x "$here/src/qsignify" ]] && native="$here/src/qsignify"

bcjar="${BCPROV_JAR:-}"
bc=""
if [[ -n "$bcjar" && -f "$bcjar" ]] && command -v javac >/dev/null; then
  mkdir -p "$tmp/classes"
  javac -cp "$bcjar" -d "$tmp/classes" "$here/java/QSignifyVerify.java"
  bc="$tmp/classes:$bcjar"
fi

pass=0
fail=0
check() { # description, command...
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  ok   $desc"; pass=$((pass + 1))
  else
    echo "  FAIL $desc"; fail=$((fail + 1))
  fi
}
check_fail() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  FAIL $desc (unexpectedly accepted)"; fail=$((fail + 1))
  else
    echo "  ok   $desc"; pass=$((pass + 1))
  fi
}

for a in Q2 Q3 Q5; do
  echo "== $a =="

  # --- python reference ---
  python3 "$here/qsignify.py" -G -a "$a" -p "$tmp/$a.p.pub" -s "$tmp/$a.p.sec" -c "py $a" >/dev/null
  python3 "$here/qsignify.py" -S -s "$tmp/$a.p.sec" -m "$tmp/msg" -x "$tmp/$a.p.sig" >/dev/null
  check "python: verifies own signature" \
    python3 "$here/qsignify.py" -V -p "$tmp/$a.p.pub" -m "$tmp/msg" -x "$tmp/$a.p.sig" -q
  check_fail "python: rejects tampered message" \
    python3 "$here/qsignify.py" -V -p "$tmp/$a.p.pub" -m "$tmp/bad" -x "$tmp/$a.p.sig" -q
  python3 "$here/qsignify.py" -G -a "$a" -p "$tmp/$a.other.pub" -s "$tmp/$a.other.sec" -c other >/dev/null
  check_fail "python: rejects wrong key" \
    python3 "$here/qsignify.py" -V -p "$tmp/$a.other.pub" -m "$tmp/msg" -x "$tmp/$a.p.sig" -q

  # --- native liboqs reference ---
  if [[ -n "$native" ]]; then
    "$native" -G -a "$a" -p "$tmp/$a.c.pub" -s "$tmp/$a.c.sec" -c "native $a" >/dev/null
    "$native" -S -s "$tmp/$a.c.sec" -m "$tmp/msg" -x "$tmp/$a.c.sig" >/dev/null
    check "native: verifies own signature" \
      "$native" -V -p "$tmp/$a.c.pub" -m "$tmp/msg" -x "$tmp/$a.c.sig" -q
    check_fail "native: rejects tampered message" \
      "$native" -V -p "$tmp/$a.c.pub" -m "$tmp/bad" -x "$tmp/$a.c.sig" -q
    check_fail "native: rejects wrong key" \
      "$native" -V -p "$tmp/$a.other.pub" -m "$tmp/msg" -x "$tmp/$a.c.sig" -q

    check "cross: python verifies native" \
      python3 "$here/qsignify.py" -V -p "$tmp/$a.c.pub" -m "$tmp/msg" -x "$tmp/$a.c.sig" -q
    check "cross: native verifies python" \
      "$native" -V -p "$tmp/$a.p.pub" -m "$tmp/msg" -x "$tmp/$a.p.sig" -q
  fi

  # --- BouncyCastle ---
  if [[ -n "$bc" ]]; then
    check "BC: verifies python" \
      java -cp "$bc" QSignifyVerify "$tmp/$a.p.pub" "$tmp/msg" "$tmp/$a.p.sig"
  fi
  if [[ -n "$bc" && -n "$native" ]]; then
    check "BC: verifies native" \
      java -cp "$bc" QSignifyVerify "$tmp/$a.c.pub" "$tmp/msg" "$tmp/$a.c.sig"
  fi
done

echo
echo "passed: $pass   failed: $fail"
[[ -n "$native" ]] || echo "(native tests skipped: build with 'make -C src')"
[[ -n "$bc" ]] || echo "(BouncyCastle tests skipped: set BCPROV_JAR=/path/to/bcprov-jdk18on-1.79.jar)"
[[ "$fail" -eq 0 ]]
