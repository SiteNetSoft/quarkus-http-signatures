package org.sitenetsoft.httpsignatures;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Parses keys from PEM (PKCS#8, SubjectPublicKeyInfo, PKCS#1) and JWK (RSA, EC, OKP/Ed25519, oct).
 */
public final class Keys {

    private static final Pattern PEM_BLOCK = Pattern.compile(
            "-----BEGIN ([A-Z0-9 ]+)-----\\s*([A-Za-z0-9+/=\\s]+?)\\s*-----END \\1-----");
    private static final ObjectMapper JSON = new ObjectMapper();

    private Keys() {
    }

    /**
     * The first key in a PEM document.
     */
    public static Key parsePem(String pem) {
        List<Key> keys = parsePemAll(pem);
        if (keys.isEmpty()) {
            throw new IllegalArgumentException("No PEM key block found");
        }
        return keys.get(0);
    }

    /**
     * Every key in a PEM document, in order (a private key file may also carry its public key).
     */
    public static List<Key> parsePemAll(String pem) {
        List<Key> keys = new ArrayList<>();
        Matcher m = PEM_BLOCK.matcher(pem);
        while (m.find()) {
            String type = m.group(1);
            byte[] der = Base64.getMimeDecoder().decode(m.group(2));
            keys.add(switch (type) {
                case "PRIVATE KEY" -> privateKey(der);
                case "PUBLIC KEY" -> publicKey(der);
                case "RSA PRIVATE KEY" -> privateKey(Der.pkcs1ToPkcs8(der));
                case "RSA PUBLIC KEY" -> publicKey(Der.pkcs1ToSpki(der));
                case "EC PRIVATE KEY" -> privateKey(Der.sec1ToPkcs8(der));
                default -> throw new IllegalArgumentException("Unsupported PEM block: " + type);
            });
        }
        return keys;
    }

    private static Key privateKey(byte[] pkcs8) {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8);
        GeneralSecurityException last = null;
        for (String alg : new String[] { "RSA", "RSASSA-PSS", "EC", "Ed25519" }) {
            try {
                return KeyFactory.getInstance(alg).generatePrivate(spec);
            } catch (GeneralSecurityException e) {
                last = e;
            }
        }
        throw new IllegalArgumentException("Unsupported private key", last);
    }

    private static Key publicKey(byte[] spki) {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(spki);
        GeneralSecurityException last = null;
        for (String alg : new String[] { "RSA", "RSASSA-PSS", "EC", "Ed25519" }) {
            try {
                return KeyFactory.getInstance(alg).generatePublic(spec);
            } catch (GeneralSecurityException e) {
                last = e;
            }
        }
        throw new IllegalArgumentException("Unsupported public key", last);
    }

    /**
     * Parses a JWK. A JWK with a private part yields the private key; otherwise the public key (or secret).
     */
    public static Key parseJwk(String json) {
        JsonNode jwk;
        try {
            jwk = JSON.readTree(json);
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid JWK JSON", e);
        }
        String kty = text(jwk, "kty");
        try {
            return switch (kty) {
                case "RSA" -> rsa(jwk);
                case "EC" -> ec(jwk);
                case "OKP" -> okp(jwk);
                case "oct" -> hmacKey(b64(jwk, "k"));
                default -> throw new IllegalArgumentException("Unsupported JWK kty: " + kty);
            };
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid JWK", e);
        }
    }

    public static SecretKey hmacKey(byte[] secret) {
        return new SecretKeySpec(secret, "HmacSHA256");
    }

    private static Key rsa(JsonNode jwk) throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        BigInteger n = big(jwk, "n");
        BigInteger e = big(jwk, "e");
        if (!jwk.hasNonNull("d")) {
            return kf.generatePublic(new RSAPublicKeySpec(n, e));
        }
        BigInteger d = big(jwk, "d");
        if (jwk.hasNonNull("p") && jwk.hasNonNull("q") && jwk.hasNonNull("dp") && jwk.hasNonNull("dq") && jwk.hasNonNull("qi")) {
            return kf.generatePrivate(new RSAPrivateCrtKeySpec(n, e, d, big(jwk, "p"), big(jwk, "q"), big(jwk, "dp"),
                    big(jwk, "dq"), big(jwk, "qi")));
        }
        return kf.generatePrivate(new RSAPrivateKeySpec(n, d));
    }

    private static Key ec(JsonNode jwk) throws GeneralSecurityException {
        String crv = text(jwk, "crv");
        String curve = switch (crv) {
            case "P-256" -> "secp256r1";
            case "P-384" -> "secp384r1";
            default -> throw new IllegalArgumentException("Unsupported EC curve: " + crv);
        };
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(curve));
        ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
        KeyFactory kf = KeyFactory.getInstance("EC");
        if (jwk.hasNonNull("d")) {
            return kf.generatePrivate(new ECPrivateKeySpec(big(jwk, "d"), spec));
        }
        return kf.generatePublic(new ECPublicKeySpec(new ECPoint(big(jwk, "x"), big(jwk, "y")), spec));
    }

    private static Key okp(JsonNode jwk) throws GeneralSecurityException {
        if (!"Ed25519".equals(text(jwk, "crv"))) {
            throw new IllegalArgumentException("Unsupported OKP curve: " + text(jwk, "crv"));
        }
        KeyFactory kf = KeyFactory.getInstance("Ed25519");
        if (jwk.hasNonNull("d")) {
            return kf.generatePrivate(new PKCS8EncodedKeySpec(Der.ed25519Pkcs8(b64(jwk, "d"))));
        }
        return kf.generatePublic(new X509EncodedKeySpec(Der.ed25519Spki(b64(jwk, "x"))));
    }

    private static String text(JsonNode node, String field) {
        JsonNode n = node.get(field);
        if (n == null || !n.isTextual()) {
            throw new IllegalArgumentException("JWK is missing '" + field + "'");
        }
        return n.asText();
    }

    private static byte[] b64(JsonNode node, String field) {
        return Base64.getUrlDecoder().decode(text(node, field));
    }

    private static BigInteger big(JsonNode node, String field) {
        return new BigInteger(1, b64(node, field));
    }
}
