/*
 * QSignifyVerify - BouncyCastle interoperability check for qsignify files.
 *
 * Verifies a SPEC.md hybrid signature using BouncyCastle only:
 *   - Ed25519       (org.bouncycastle.crypto.signers.Ed25519Signer)
 *   - ML-DSA-44/65/87 (org.bouncycastle.pqc.crypto.mldsa.MLDSASigner)
 *
 * Build (Maven):
 *   mvn -q -f java/pom.xml package
 *   java -cp java/target/qsignify-bc.jar:$HOME/.m2/.../bcprov-jdk18on-1.79.jar \
 *        QSignifyVerify <pub> <msg> <sig>
 *
 * Or with a manually fetched bcprov jar:
 *   javac -cp bcprov-jdk18on-1.79.jar java/QSignifyVerify.java
 *   java  -cp .:bcprov-jdk18on-1.79.jar QSignifyVerify <pub> <msg> <sig>
 *
 * SPDX-License-Identifier: ISC
 */

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

public final class QSignifyVerify {

    private static final String COMMENTHDR = "untrusted comment: ";
    private static final int KEYNUM_LEN = 8;
    private static final int ED25519_PUB_LEN = 32;
    private static final int ED25519_SIG_LEN = 64;

    private static byte[] payload(String path) throws Exception {
        String text = new String(Files.readAllBytes(Paths.get(path)), "US-ASCII");
        String[] lines = text.split("\n");
        if (lines.length < 2 || !lines[0].startsWith(COMMENTHDR)) {
            throw new IllegalArgumentException("invalid qsignify file: " + path);
        }
        return Base64.getMimeDecoder().decode(lines[1].trim());
    }

    private static MLDSAParameters paramsFor(String tag) {
        switch (tag) {
            case "Q2": return MLDSAParameters.ml_dsa_44;
            case "Q3": return MLDSAParameters.ml_dsa_65;
            case "Q5": return MLDSAParameters.ml_dsa_87;
            default: throw new IllegalArgumentException("unknown tag " + tag);
        }
    }

    private static boolean verify(byte[] pub, byte[] sig, byte[] msg) {
        String pubTag = new String(pub, 0, 2, java.nio.charset.StandardCharsets.US_ASCII);
        String sigTag = new String(sig, 0, 2, java.nio.charset.StandardCharsets.US_ASCII);
        if (!pubTag.equals(sigTag)) {
            System.err.println("tag mismatch: " + pubTag + " vs " + sigTag);
            return false;
        }

        int po = 2;
        byte[] pubKeynum = java.util.Arrays.copyOfRange(pub, po, po + KEYNUM_LEN);
        po += KEYNUM_LEN;
        byte[] edPub = java.util.Arrays.copyOfRange(pub, po, po + ED25519_PUB_LEN);
        po += ED25519_PUB_LEN;
        byte[] pqPub = java.util.Arrays.copyOfRange(pub, po, pub.length);

        int so = 2;
        byte[] sigKeynum = java.util.Arrays.copyOfRange(sig, so, so + KEYNUM_LEN);
        so += KEYNUM_LEN;
        byte[] edSig = java.util.Arrays.copyOfRange(sig, so, so + ED25519_SIG_LEN);
        so += ED25519_SIG_LEN;
        byte[] pqSig = java.util.Arrays.copyOfRange(sig, so, sig.length);

        if (!java.util.Arrays.equals(pubKeynum, sigKeynum)) {
            System.err.println("keynum mismatch");
            return false;
        }

        Ed25519Signer ed = new Ed25519Signer();
        ed.init(false, new Ed25519PublicKeyParameters(edPub, 0));
        ed.update(msg, 0, msg.length);
        boolean edOk = ed.verifySignature(edSig);

        MLDSASigner pq = new MLDSASigner();
        pq.init(false, new MLDSAPublicKeyParameters(paramsFor(pubTag), pqPub));
        pq.update(msg, 0, msg.length);
        boolean pqOk = pq.verifySignature(pqSig);

        System.out.println("  Ed25519 : " + (edOk ? "OK" : "FAIL"));
        System.out.println("  ML-DSA  : " + (pqOk ? "OK" : "FAIL"));
        return edOk && pqOk;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("usage: QSignifyVerify <pub> <msg> <sig>");
            System.exit(2);
        }
        byte[] pub = payload(args[0]);
        byte[] msg = Files.readAllBytes(Paths.get(args[1]));
        byte[] sig = payload(args[2]);

        boolean ok = verify(pub, sig, msg);
        System.out.println(ok ? "Signature Verified" : "signature verification failed");
        System.exit(ok ? 0 : 1);
    }
}
