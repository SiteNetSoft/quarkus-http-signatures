package org.sitenetsoft.httpsignatures;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

class KeysTest {

    static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }

    static KeyPair generate(String alg, Object spec) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance(alg);
        if (spec instanceof Integer bits) {
            g.initialize(bits);
        } else if (spec != null) {
            g.initialize((ECGenParameterSpec) spec);
        }
        return g.generateKeyPair();
    }

    @Test
    void parsesPkcs8AndSpkiPem() throws Exception {
        for (KeyPair kp : List.of(generate("RSA", 2048), generate("EC", new ECGenParameterSpec("secp256r1")),
                generate("Ed25519", null))) {
            Key priv = Keys.parsePem(pem("PRIVATE KEY", kp.getPrivate().getEncoded()));
            Key pub = Keys.parsePem(pem("PUBLIC KEY", kp.getPublic().getEncoded()));
            assertInstanceOf(PrivateKey.class, priv);
            assertInstanceOf(PublicKey.class, pub);
            assertArrayEquals(kp.getPrivate().getEncoded(), priv.getEncoded());
            assertArrayEquals(kp.getPublic().getEncoded(), pub.getEncoded());
        }
    }

    @Test
    void parsesPemWithSeveralBlocks() throws Exception {
        KeyPair kp = generate("Ed25519", null);
        List<Key> keys = Keys.parsePemAll(pem("PRIVATE KEY", kp.getPrivate().getEncoded()) + pem("PUBLIC KEY", kp.getPublic().getEncoded()));
        assertEquals(2, keys.size());
        assertInstanceOf(PrivateKey.class, keys.get(0));
        assertInstanceOf(PublicKey.class, keys.get(1));
    }

    @Test
    void parsesPkcs1RsaPem() throws Exception {
        // RFC 9421 Appendix B.1.1 test-key-rsa (PKCS#1 "RSA PUBLIC KEY" / "RSA PRIVATE KEY")
        String pub = """
                -----BEGIN RSA PUBLIC KEY-----
                MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw
                WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq
                MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg
                kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P
                uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ
                PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB
                -----END RSA PUBLIC KEY-----
                """;
        Key key = Keys.parsePem(pub);
        assertInstanceOf(RSAPublicKey.class, key);
        assertEquals(2048, ((RSAPublicKey) key).getModulus().bitLength());
    }

    @Test
    void parsesJwks() throws Exception {
        Key oct = Keys.parseJwk("{\"kty\":\"oct\",\"k\":\"uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJJBq-WbGzaWzwLlYCdELgVYqCrlEGQ7X0dZQ6oWD6Zg2oDA7h1VaQsf5xuZSxIjvC1SBu\"}");
        assertInstanceOf(SecretKey.class, oct);
        assertEquals(96, oct.getEncoded().length);

        KeyPair rsa = generate("RSA", 2048);
        RSAPublicKey rpub = (RSAPublicKey) rsa.getPublic();
        String n = Base64.getUrlEncoder().withoutPadding().encodeToString(unsigned(rpub.getModulus().toByteArray()));
        String e = Base64.getUrlEncoder().withoutPadding().encodeToString(unsigned(rpub.getPublicExponent().toByteArray()));
        Key parsed = Keys.parseJwk("{\"kty\":\"RSA\",\"n\":\"" + n + "\",\"e\":\"" + e + "\"}");
        assertArrayEquals(rpub.getEncoded(), parsed.getEncoded());

        KeyPair ed = generate("Ed25519", null);
        byte[] spki = ed.getPublic().getEncoded();
        byte[] raw = java.util.Arrays.copyOfRange(spki, spki.length - 32, spki.length);
        String x = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        Key edParsed = Keys.parseJwk("{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + x + "\"}");
        assertArrayEquals(spki, edParsed.getEncoded());
    }

    static byte[] unsigned(byte[] b) {
        return b[0] == 0 ? java.util.Arrays.copyOfRange(b, 1, b.length) : b;
    }

    @Test
    void detectsKeyTypes() throws Exception {
        assertEquals(KeyType.RSA, KeyType.of(generate("RSA", 2048).getPublic()));
        assertEquals(KeyType.EC_P256, KeyType.of(generate("EC", new ECGenParameterSpec("secp256r1")).getPrivate()));
        assertEquals(KeyType.EC_P384, KeyType.of(generate("EC", new ECGenParameterSpec("secp384r1")).getPublic()));
        assertEquals(KeyType.ED25519, KeyType.of(generate("Ed25519", null).getPublic()));
        assertEquals(KeyType.HMAC, KeyType.of(Keys.hmacKey(new byte[32])));
    }
}
