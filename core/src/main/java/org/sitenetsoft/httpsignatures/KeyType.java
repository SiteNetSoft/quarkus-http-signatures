package org.sitenetsoft.httpsignatures;

import java.security.Key;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

import javax.crypto.SecretKey;

public enum KeyType {
    RSA,
    EC_P256,
    EC_P384,
    ED25519,
    HMAC;

    public static KeyType of(Key key) {
        if (key instanceof SecretKey) {
            return HMAC;
        }
        if (key instanceof RSAKey) {
            return RSA;
        }
        if (key instanceof ECKey ec) {
            int bits = ec.getParams().getCurve().getField().getFieldSize();
            return switch (bits) {
                case 256 -> EC_P256;
                case 384 -> EC_P384;
                default -> throw new IllegalArgumentException("Unsupported EC curve size: " + bits);
            };
        }
        String alg = key.getAlgorithm();
        if ("Ed25519".equalsIgnoreCase(alg) || "EdDSA".equalsIgnoreCase(alg)) {
            return ED25519;
        }
        throw new IllegalArgumentException("Unsupported key type: " + key.getClass().getName() + " (" + alg + ")");
    }
}
