package org.sitenetsoft.httpsignatures;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import javax.crypto.Mac;

import org.sitenetsoft.httpsignatures.HttpSignatureException.Reason;

/**
 * Maps algorithms to the JDK providers. ECDSA signatures are raw {@code r||s} under RFC 9421 and DER under Cavage.
 */
final class Jca {

    private Jca() {
    }

    static byte[] sign(Algorithm alg, Scheme scheme, Key key, byte[] data) {
        try {
            if (alg == Algorithm.HMAC_SHA256) {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(key);
                return mac.doFinal(data);
            }
            Signature sig = signature(alg, scheme);
            sig.initSign((PrivateKey) key);
            sig.update(data);
            return sig.sign();
        } catch (GeneralSecurityException | ClassCastException e) {
            throw new HttpSignatureException(Reason.INVALID_SIGNATURE, "Signing failed with " + alg.id(), e);
        }
    }

    static boolean verify(Algorithm alg, Scheme scheme, Key key, byte[] data, byte[] signature) {
        try {
            if (alg == Algorithm.HMAC_SHA256) {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(key);
                return MessageDigest.isEqual(mac.doFinal(data), signature);
            }
            Signature sig = signature(alg, scheme);
            sig.initVerify((PublicKey) key);
            sig.update(data);
            return sig.verify(signature);
        } catch (GeneralSecurityException | ClassCastException | IllegalArgumentException e) {
            return false;
        }
    }

    private static Signature signature(Algorithm alg, Scheme scheme) throws GeneralSecurityException {
        boolean p1363 = scheme == Scheme.RFC9421;
        return switch (alg) {
            case RSA_V1_5_SHA256, RSA_SHA256 -> Signature.getInstance("SHA256withRSA");
            case RSA_PSS_SHA512 -> {
                Signature s = Signature.getInstance("RSASSA-PSS");
                s.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1));
                yield s;
            }
            case ECDSA_P256_SHA256 -> Signature.getInstance(p1363 ? "SHA256withECDSAinP1363Format" : "SHA256withECDSA");
            case ECDSA_P384_SHA384 -> Signature.getInstance(p1363 ? "SHA384withECDSAinP1363Format" : "SHA384withECDSA");
            case ED25519 -> Signature.getInstance("Ed25519");
            case HMAC_SHA256 -> throw new IllegalStateException("HMAC handled separately");
            case HS2019 -> throw new HttpSignatureException(Reason.UNSUPPORTED_ALGORITHM, "hs2019 must be resolved to a concrete algorithm first");
        };
    }
}
