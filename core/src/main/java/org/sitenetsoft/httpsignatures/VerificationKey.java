package org.sitenetsoft.httpsignatures;

import java.security.Key;
import java.util.Optional;

/**
 * A public or secret key used to verify, optionally pinned to one algorithm. {@code toString()} never reveals the key.
 */
public record VerificationKey(String keyId, Optional<Algorithm> algorithm, Key key) {

    public VerificationKey {
        if (keyId == null || key == null) {
            throw new IllegalArgumentException("keyId and key are required");
        }
        algorithm = algorithm == null ? Optional.empty() : algorithm;
    }

    public KeyType keyType() {
        return KeyType.of(key);
    }

    @Override
    public String toString() {
        return "VerificationKey[keyId=" + keyId + ", algorithm=" + algorithm.map(Algorithm::id).orElse("from key") + "]";
    }
}
