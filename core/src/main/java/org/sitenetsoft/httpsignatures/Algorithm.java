package org.sitenetsoft.httpsignatures;

import java.util.Optional;

/**
 * Signature algorithms. RFC 9421 names and the Cavage names differ; {@code ed25519} is shared. {@code hs2019}
 * carries no algorithm: it is derived from the key type.
 */
public enum Algorithm {
    RSA_V1_5_SHA256("rsa-v1_5-sha256", KeyType.RSA, true, false),
    RSA_PSS_SHA512("rsa-pss-sha512", KeyType.RSA, true, false),
    ECDSA_P256_SHA256("ecdsa-p256-sha256", KeyType.EC_P256, true, false),
    ECDSA_P384_SHA384("ecdsa-p384-sha384", KeyType.EC_P384, true, false),
    ED25519("ed25519", KeyType.ED25519, true, true),
    HMAC_SHA256("hmac-sha256", KeyType.HMAC, true, false),
    RSA_SHA256("rsa-sha256", KeyType.RSA, false, true),
    HS2019("hs2019", null, false, true);

    private final String id;
    private final KeyType keyType;
    private final boolean rfc9421;
    private final boolean cavage;

    Algorithm(String id, KeyType keyType, boolean rfc9421, boolean cavage) {
        this.id = id;
        this.keyType = keyType;
        this.rfc9421 = rfc9421;
        this.cavage = cavage;
    }

    public String id() {
        return id;
    }

    /**
     * The key type this algorithm requires, or {@code null} for {@link #HS2019}.
     */
    public KeyType keyType() {
        return keyType;
    }

    public boolean isRfc9421() {
        return rfc9421;
    }

    public boolean isCavage() {
        return cavage;
    }

    public static Optional<Algorithm> fromId(String id) {
        if (id == null) {
            return Optional.empty();
        }
        for (Algorithm a : values()) {
            if (a.id.equalsIgnoreCase(id)) {
                return Optional.of(a);
            }
        }
        return Optional.empty();
    }

    /**
     * The concrete algorithm {@code hs2019} means for a key type (draft-cavage-12 section 6.3).
     */
    public static Algorithm forHs2019(KeyType keyType) {
        return switch (keyType) {
            case RSA -> RSA_PSS_SHA512;
            case ED25519 -> ED25519;
            case EC_P256 -> ECDSA_P256_SHA256;
            case EC_P384 -> ECDSA_P384_SHA384;
            case HMAC -> HMAC_SHA256;
        };
    }
}
