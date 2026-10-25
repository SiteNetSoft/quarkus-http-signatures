package org.sitenetsoft.httpsignatures;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

/**
 * {@code Content-Digest} (RFC 9530) and legacy {@code Digest} (RFC 3230) headers.
 */
public final class Digests {

    private Digests() {
    }

    public static byte[] digest(byte[] body, DigestAlgorithm alg) {
        try {
            return MessageDigest.getInstance(alg.jca()).digest(body);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * {@code sha-256=:base64:} as an RFC 9530 dictionary member.
     */
    public static String contentDigest(byte[] body, DigestAlgorithm alg) {
        return alg.id() + "=:" + Base64.getEncoder().encodeToString(digest(body, alg)) + ":";
    }

    /**
     * True when the header names at least one known algorithm and every known one matches the body.
     */
    public static boolean verifyContentDigest(String headerValue, byte[] body) {
        if (headerValue == null || headerValue.isBlank()) {
            return false;
        }
        Map<String, Object> dict;
        try {
            dict = StructuredFields.parseDictionary(headerValue);
        } catch (HttpSignatureException e) {
            return false;
        }
        boolean known = false;
        for (Map.Entry<String, Object> e : dict.entrySet()) {
            Optional<DigestAlgorithm> alg = DigestAlgorithm.fromId(e.getKey());
            if (alg.isEmpty()) {
                continue;
            }
            if (!(e.getValue() instanceof StructuredFields.Item item) || !(item.value() instanceof byte[] expected)) {
                return false;
            }
            known = true;
            if (!MessageDigest.isEqual(expected, digest(body, alg.get()))) {
                return false;
            }
        }
        return known;
    }

    /**
     * Legacy {@code Digest: SHA-256=base64} (RFC 3230), as the Fediverse uses it.
     */
    public static String legacyDigest(byte[] body) {
        return "SHA-256=" + Base64.getEncoder().encodeToString(digest(body, DigestAlgorithm.SHA_256));
    }

    /**
     * True when a {@code SHA-256} (or {@code sha-256}) entry is present and matches the body.
     */
    public static boolean verifyLegacyDigest(String headerValue, byte[] body) {
        if (headerValue == null) {
            return false;
        }
        for (String part : headerValue.split(",")) {
            int eq = part.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String alg = part.substring(0, eq).strip();
            String value = part.substring(eq + 1).strip();
            DigestAlgorithm d = "SHA-256".equalsIgnoreCase(alg) ? DigestAlgorithm.SHA_256
                    : "SHA-512".equalsIgnoreCase(alg) ? DigestAlgorithm.SHA_512 : null;
            if (d == null) {
                continue;
            }
            try {
                return MessageDigest.isEqual(Base64.getDecoder().decode(value), digest(body, d));
            } catch (IllegalArgumentException e) {
                return false;
            }
        }
        return false;
    }
}
