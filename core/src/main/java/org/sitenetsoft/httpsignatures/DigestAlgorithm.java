package org.sitenetsoft.httpsignatures;

import java.util.Optional;

/**
 * Body digest algorithms (RFC 9530 registry subset).
 */
public enum DigestAlgorithm {
    SHA_256("sha-256", "SHA-256"),
    SHA_512("sha-512", "SHA-512");

    private final String id;
    private final String jca;

    DigestAlgorithm(String id, String jca) {
        this.id = id;
        this.jca = jca;
    }

    public String id() {
        return id;
    }

    public String jca() {
        return jca;
    }

    public static Optional<DigestAlgorithm> fromId(String id) {
        for (DigestAlgorithm a : values()) {
            if (a.id.equalsIgnoreCase(id)) {
                return Optional.of(a);
            }
        }
        return Optional.empty();
    }
}
