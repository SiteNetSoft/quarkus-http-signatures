package org.sitenetsoft.httpsignatures;

import java.security.Key;

/**
 * A private or secret key with its key id and algorithm. {@code toString()} never reveals the key.
 */
public record SigningKey(String keyId, Algorithm algorithm, Key key) {

    public SigningKey {
        if (keyId == null || algorithm == null || key == null) {
            throw new IllegalArgumentException("keyId, algorithm and key are required");
        }
        KeyType type = KeyType.of(key);
        if (algorithm != Algorithm.HS2019 && algorithm.keyType() != type) {
            throw new IllegalArgumentException("Algorithm " + algorithm.id() + " needs a " + algorithm.keyType() + " key, got " + type);
        }
    }

    public KeyType keyType() {
        return KeyType.of(key);
    }

    @Override
    public String toString() {
        return "SigningKey[keyId=" + keyId + ", algorithm=" + algorithm.id() + "]";
    }
}
