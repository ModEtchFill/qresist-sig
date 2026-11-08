/*
 * qsignify.c - signify-shaped hybrid signatures: Ed25519 + ML-DSA.
 *
 * Native backend: liboqs (ML-DSA-44/65/87) + OpenSSL EVP (Ed25519).
 * Produces and consumes the SPEC.md wire format, interoperable with
 * qsignify.py and the BouncyCastle verifier in java/.
 *
 * The secret-key file layout here is backend-specific (raw Ed25519 seed +
 * liboqs ML-DSA secret key); public keys and signatures are shared.
 *
 * SPDX-License-Identifier: ISC
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <oqs/oqs.h>

#define COMMENTHDR "untrusted comment: "
#define COMMENTHDRLEN (sizeof(COMMENTHDR) - 1)
#define VERIFYWITH "verify with "
#define KEYNUMLEN 8
#define ED25519_PUBLEN 32
#define ED25519_SEEDLEN 32
#define ED25519_SIGLEN 64

struct suite {
	const char *tag;
	const char *oqs_alg;
	size_t publen;
	size_t sklen;
	size_t siglen;
};

static const struct suite suites[] = {
	{ "Q2", OQS_SIG_alg_ml_dsa_44, 1312, 2560, 2420 },
	{ "Q3", OQS_SIG_alg_ml_dsa_65, 1952, 4032, 3309 },
	{ "Q5", OQS_SIG_alg_ml_dsa_87, 2592, 4896, 4627 },
};
#define NSUITES (sizeof(suites) / sizeof(suites[0]))

static const struct suite *find_suite(const char *tag)
{
	for (size_t i = 0; i < NSUITES; i++)
		if (memcmp(tag, suites[i].tag, 2) == 0)
			return &suites[i];
	return NULL;
}

static void die(const char *msg)
{
	fprintf(stderr, "qsignify: %s\n", msg);
	exit(1);
}

static void *xmalloc(size_t n)
{
	void *p = malloc(n ? n : 1);
	if (!p)
		die("out of memory");
	return p;
}

/* ------------------------------------------------------------------ base64 */
static const char b64tab[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *b64_encode(const uint8_t *in, size_t len)
{
	size_t olen = 4 * ((len + 2) / 3);
	char *out = xmalloc(olen + 1);
	size_t i, o = 0;

	for (i = 0; i + 2 < len; i += 3) {
		uint32_t v = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
		out[o++] = b64tab[(v >> 18) & 63];
		out[o++] = b64tab[(v >> 12) & 63];
		out[o++] = b64tab[(v >> 6) & 63];
		out[o++] = b64tab[v & 63];
	}
	if (i < len) {
		uint32_t v = in[i] << 16;
		int rem = (int)(len - i);
		if (rem == 2)
			v |= in[i + 1] << 8;
		out[o++] = b64tab[(v >> 18) & 63];
		out[o++] = b64tab[(v >> 12) & 63];
		out[o++] = (rem == 2) ? b64tab[(v >> 6) & 63] : '=';
		out[o++] = '=';
	}
	out[o] = '\0';
	return out;
}

static int b64val(int c)
{
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}

static void random_bytes(uint8_t *buf, size_t len)
{
	while (len > 0) {
		ssize_t n = getrandom(buf, len, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			die("RNG failure");
		}
		buf += n;
		len -= (size_t)n;
	}
}

static uint8_t *b64_decode(const char *in, size_t inlen, size_t *outlen)
{
	uint8_t *out = xmalloc(inlen / 4 * 3 + 4);
	size_t o = 0, i;
	uint32_t acc = 0;
	int nbits = 0;

	for (i = 0; i < inlen; i++) {
		int c = (unsigned char)in[i];
		int v;
		if (c == '\r' || c == '\n' || c == ' ' || c == '\t' || c == '=')
			continue;
		v = b64val(c);
		if (v < 0) {
			free(out);
			return NULL;
		}
		acc = (acc << 6) | (uint32_t)v;
		nbits += 6;
		if (nbits >= 8) {
			nbits -= 8;
			out[o++] = (acc >> nbits) & 0xff;
		}
	}
	*outlen = o;
	return out;
}

/* ------------------------------------------------------------------- files */
static uint8_t *read_file(const char *path, size_t *lenp)
{
	FILE *f = strcmp(path, "-") == 0 ? stdin : fopen(path, "rb");
	size_t cap = 1 << 16, len = 0;
	uint8_t *buf;

	if (!f)
		die("cannot open file");
	buf = xmalloc(cap);
	for (;;) {
		size_t n;
		if (len == cap) {
			cap *= 2;
			buf = realloc(buf, cap);
			if (!buf)
				die("out of memory");
		}
		n = fread(buf + len, 1, cap - len, f);
		len += n;
		if (n == 0)
			break;
	}
	if (f != stdin)
		fclose(f);
	*lenp = len;
	return buf;
}

static void write_file(const char *path, const void *buf, size_t len, mode_t mode)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, mode);
	if (fd < 0)
		die("cannot open output file");
	if (write(fd, buf, len) != (ssize_t)len)
		die("short write");
	close(fd);
}

/* Parse "untrusted comment: ...\n<base64>\n" and return decoded bytes. */
static uint8_t *parse_b64_file(const char *path, size_t *lenp, char *comment,
    size_t commentcap)
{
	size_t rawlen;
	uint8_t *raw = read_file(path, &rawlen);
	char *nl, *nl2;
	uint8_t *out;
	size_t outlen;

	if (rawlen < COMMENTHDRLEN ||
	    memcmp(raw, COMMENTHDR, COMMENTHDRLEN) != 0)
		die("invalid comment; must start with 'untrusted comment: '");
	nl = memchr(raw, '\n', rawlen);
	if (!nl)
		die("missing newline after comment");
	if (comment) {
		size_t clen = (size_t)(nl - (char *)raw) - COMMENTHDRLEN;
		if (clen >= commentcap)
			clen = commentcap - 1;
		memcpy(comment, raw + COMMENTHDRLEN, clen);
		comment[clen] = '\0';
	}
	nl2 = memchr(nl + 1, '\n', rawlen - (nl + 1 - (char *)raw));
	if (!nl2)
		nl2 = (char *)raw + rawlen;
	out = b64_decode(nl + 1, (size_t)(nl2 - (nl + 1)), &outlen);
	free(raw);
	if (!out)
		die("invalid base64 payload");
	*lenp = outlen;
	return out;
}

static void write_b64_file(const char *path, const char *comment,
    const uint8_t *buf, size_t len, mode_t mode)
{
	char *b64 = b64_encode(buf, len);
	size_t total = COMMENTHDRLEN + strlen(comment) + 1 + strlen(b64) + 1 + 1;
	char *out = xmalloc(total);
	int n = snprintf(out, total, "%s%s\n%s\n", COMMENTHDR, comment, b64);

	if (n < 0 || (size_t)n >= total)
		die("comment too long");
	write_file(path, out, (size_t)n, mode);
	free(b64);
	free(out);
}

/* ------------------------------------------------------------- Ed25519 EVP */
static int ed_sign(const uint8_t seed[ED25519_SEEDLEN], const uint8_t *msg,
    size_t msglen, uint8_t sig[ED25519_SIGLEN])
{
	EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
	    seed, ED25519_SEEDLEN);
	EVP_MD_CTX *ctx = pkey ? EVP_MD_CTX_new() : NULL;
	size_t siglen = ED25519_SIGLEN;
	int ok = 0;

	if (ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
	    EVP_DigestSign(ctx, sig, &siglen, msg, msglen) == 1 &&
	    siglen == ED25519_SIGLEN)
		ok = 1;
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return ok;
}

static int ed_verify(const uint8_t pub[ED25519_PUBLEN], const uint8_t *msg,
    size_t msglen, const uint8_t sig[ED25519_SIGLEN])
{
	EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
	    pub, ED25519_PUBLEN);
	EVP_MD_CTX *ctx = pkey ? EVP_MD_CTX_new() : NULL;
	int ok = 0;

	if (ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
	    EVP_DigestVerify(ctx, sig, ED25519_SIGLEN, msg, msglen) == 1)
		ok = 1;
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return ok;
}

/* ------------------------------------------------------------------ keygen */
static void generate(const char *pubpath, const char *secpath,
    const struct suite *s, const char *comment)
{
	OQS_SIG *oqs = OQS_SIG_new(s->oqs_alg);
	uint8_t *pq_pub, *pq_sk, ed_seed[ED25519_SEEDLEN], ed_pub[ED25519_PUBLEN];
	uint8_t keynum[KEYNUMLEN];
	uint8_t *pub, *sec;
	size_t publen = 2 + KEYNUMLEN + ED25519_PUBLEN + s->publen;
	size_t seclen = 2 + KEYNUMLEN + ED25519_SEEDLEN + s->sklen;
	char commentbuf[1024];
	EVP_PKEY *edp = NULL;
	size_t edpublen = ED25519_PUBLEN;

	if (!oqs)
		die("liboqs does not support the requested ML-DSA parameter set");
	pq_pub = xmalloc(s->publen);
	pq_sk = xmalloc(s->sklen);
	if (OQS_SIG_keypair(oqs, pq_pub, pq_sk) != OQS_SUCCESS)
		die("ML-DSA key generation failed");

	random_bytes(ed_seed, ED25519_SEEDLEN);
	random_bytes(keynum, KEYNUMLEN);

	edp = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, ed_seed,
	    ED25519_SEEDLEN);
	if (!edp || EVP_PKEY_get_raw_public_key(edp, ed_pub, &edpublen) != 1)
		die("Ed25519 key derivation failed");
	EVP_PKEY_free(edp);

	pub = xmalloc(publen);
	memcpy(pub, s->tag, 2);
	memcpy(pub + 2, keynum, KEYNUMLEN);
	memcpy(pub + 2 + KEYNUMLEN, ed_pub, ED25519_PUBLEN);
	memcpy(pub + 2 + KEYNUMLEN + ED25519_PUBLEN, pq_pub, s->publen);

	sec = xmalloc(seclen);
	memcpy(sec, s->tag, 2);
	memcpy(sec + 2, keynum, KEYNUMLEN);
	memcpy(sec + 2 + KEYNUMLEN, ed_seed, ED25519_SEEDLEN);
	memcpy(sec + 2 + KEYNUMLEN + ED25519_SEEDLEN, pq_sk, s->sklen);

	snprintf(commentbuf, sizeof(commentbuf), "%s public key",
	    comment ? comment : "qsignify");
	write_b64_file(pubpath, commentbuf, pub, publen, 0666);
	snprintf(commentbuf, sizeof(commentbuf), "%s secret key",
	    comment ? comment : "qsignify");
	write_b64_file(secpath, commentbuf, sec, seclen, 0600);

	free(pq_pub);
	free(pq_sk);
	free(pub);
	free(sec);
	OQS_SIG_free(oqs);
}

/* --------------------------------------------------------------------- sign */
static void sign_file(const char *secpath, const char *msgpath,
    const char *sigpath)
{
	char comment[1024];
	size_t seclen, msglen, siglen;
	uint8_t *sec = parse_b64_file(secpath, &seclen, comment, sizeof(comment));
	uint8_t *msg = read_file(msgpath, &msglen);
	const struct suite *s;
	OQS_SIG *oqs;
	uint8_t *sig, ed_sig[ED25519_SIGLEN];
	uint8_t *pq_sig;
	size_t pq_siglen;
	char sigcomment[2048];
	size_t expect = 2 + KEYNUMLEN + ED25519_SEEDLEN;

	s = find_suite((char *)sec);
	if (!s)
		die("unsupported algorithm tag in secret key");
	if (seclen != expect + s->sklen)
		die("malformed secret key");

	oqs = OQS_SIG_new(s->oqs_alg);
	if (!oqs)
		die("liboqs init failed");
	pq_sig = xmalloc(s->siglen);

	if (!ed_sign(sec + 2 + KEYNUMLEN, msg, msglen, ed_sig))
		die("Ed25519 signing failed");
	if (OQS_SIG_sign(oqs, pq_sig, &pq_siglen, msg, msglen,
	    sec + expect) != OQS_SUCCESS)
		die("ML-DSA signing failed");

	siglen = 2 + KEYNUMLEN + ED25519_SIGLEN + pq_siglen;
	sig = xmalloc(siglen);
	memcpy(sig, sec, 2);
	memcpy(sig + 2, sec + 2, KEYNUMLEN);
	memcpy(sig + 2 + KEYNUMLEN, ed_sig, ED25519_SIGLEN);
	memcpy(sig + 2 + KEYNUMLEN + ED25519_SIGLEN, pq_sig, pq_siglen);

	/* comment: "verify with <name>.pub" when the sec file is named *.sec */
	{
		const char *base = strrchr(secpath, '/');
		size_t blen;
		base = base ? base + 1 : secpath;
		blen = strlen(base);
		if (blen > 4 && strcmp(base + blen - 4, ".sec") == 0)
			snprintf(sigcomment, sizeof(sigcomment),
			    VERIFYWITH "%.*s.pub", (int)(blen - 4), base);
		else
			snprintf(sigcomment, sizeof(sigcomment),
			    "signature from %s", base);
	}

	write_b64_file(sigpath, sigcomment, sig, siglen, 0666);

	free(sec);
	free(msg);
	free(sig);
	free(pq_sig);
	OQS_SIG_free(oqs);
}

/* ------------------------------------------------------------------- verify */
static int verify_file(const char *pubpath, const char *msgpath,
    const char *sigpath, int quiet)
{
	char comment[1024];
	size_t publen, siglen, msglen;
	uint8_t *pub = parse_b64_file(pubpath, &publen, comment, sizeof(comment));
	uint8_t *sig = parse_b64_file(sigpath, &siglen, NULL, 0);
	uint8_t *msg = read_file(msgpath, &msglen);
	const struct suite *s = find_suite((char *)pub);
	OQS_SIG *oqs;
	int ok = 0;

	if (!s)
		die("unsupported algorithm tag in public key");
	if (memcmp(pub + 2, sig + 2, KEYNUMLEN) != 0)
		die("verification failed: checked against wrong key");
	if (memcmp(pub, sig, 2) != 0)
		die("verification failed: algorithm mismatch");
	if (publen != 2 + KEYNUMLEN + ED25519_PUBLEN + s->publen)
		die("malformed public key");
	if (siglen != 2 + KEYNUMLEN + ED25519_SIGLEN + s->siglen)
		die("malformed signature");

	oqs = OQS_SIG_new(s->oqs_alg);
	if (!oqs)
		die("liboqs init failed");

	if (!ed_verify(pub + 2 + KEYNUMLEN, msg, msglen,
	    sig + 2 + KEYNUMLEN))
		fprintf(stderr, "qsignify: Ed25519 verification failed\n");
	else if (OQS_SIG_verify(oqs, msg, msglen,
	    sig + 2 + KEYNUMLEN + ED25519_SIGLEN, s->siglen,
	    pub + 2 + KEYNUMLEN + ED25519_PUBLEN) != OQS_SUCCESS)
		fprintf(stderr, "qsignify: ML-DSA verification failed\n");
	else
		ok = 1;

	OQS_SIG_free(oqs);
	free(pub);
	free(sig);
	free(msg);

	if (ok && !quiet)
		printf("Signature Verified\n");
	return ok ? 0 : 1;
}

/* ---------------------------------------------------------------------- CLI */
static void usage(void)
{
	fprintf(stderr,
	    "usage:\n"
	    "  qsignify -G [-a Q2|Q3|Q5] [-c comment] -p pub -s sec\n"
	    "  qsignify -S -s sec -m message [-x sig]\n"
	    "  qsignify -V [-q] -p pub -m message -x sig\n");
	exit(1);
}

int main(int argc, char **argv)
{
	int gen = 0, sign = 0, verify = 0, quiet = 0, ch;
	const char *pub = NULL, *sec = NULL, *msg = NULL, *sig = NULL;
	const char *comment = "qsignify", *alg = "Q2";
	const struct suite *s;

	OQS_init();

	while ((ch = getopt(argc, argv, "GSVqp:s:m:x:c:a:")) != -1) {
		switch (ch) {
		case 'G': gen = 1; break;
		case 'S': sign = 1; break;
		case 'V': verify = 1; break;
		case 'q': quiet = 1; break;
		case 'p': pub = optarg; break;
		case 's': sec = optarg; break;
		case 'm': msg = optarg; break;
		case 'x': sig = optarg; break;
		case 'c': comment = optarg; break;
		case 'a': alg = optarg; break;
		default: usage();
		}
	}
	if (gen + sign + verify != 1)
		usage();

	if (gen) {
		s = find_suite(alg);
		if (!s)
			die("unknown suite");
		if (!pub || !sec)
			usage();
		generate(pub, sec, s, comment);
	} else if (sign) {
		if (!sec || !msg)
			usage();
		if (!sig) {
			size_t n = strlen(msg) + 5;
			char *tmp = xmalloc(n);
			snprintf(tmp, n, "%s.sig", msg);
			sign_file(sec, msg, tmp);
			free(tmp);
		} else {
			sign_file(sec, msg, sig);
		}
	} else {
		if (!pub || !msg || !sig)
			usage();
		return verify_file(pub, msg, sig, quiet);
	}
	return 0;
}
