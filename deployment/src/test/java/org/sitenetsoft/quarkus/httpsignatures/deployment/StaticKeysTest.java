package org.sitenetsoft.quarkus.httpsignatures.deployment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Optional;

import javax.crypto.SecretKey;

import jakarta.inject.Inject;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.sitenetsoft.httpsignatures.Algorithm;
import org.sitenetsoft.httpsignatures.KeyResolver;
import org.sitenetsoft.httpsignatures.KeyType;
import org.sitenetsoft.httpsignatures.Scheme;
import org.sitenetsoft.httpsignatures.SigningKey;
import org.sitenetsoft.httpsignatures.VerificationKey;
import org.sitenetsoft.quarkus.httpsignatures.HttpSignaturesConfig;
import org.sitenetsoft.quarkus.httpsignatures.NonceStore;
import org.sitenetsoft.quarkus.httpsignatures.SigningKeyProvider;
import org.sitenetsoft.quarkus.httpsignatures.StaticKeys;

import io.quarkus.test.QuarkusUnitTest;

public class StaticKeysTest {

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class)
                    .addAsResource("keys/rsa.pem").addAsResource("keys/ed25519.pem").addAsResource("keys/hmac.jwk"))
            .overrideConfigKey("quarkus.http-signatures.keys.rsa.location", "keys/rsa.pem")
            .overrideConfigKey("quarkus.http-signatures.keys.ed.location", "keys/ed25519.pem")
            .overrideConfigKey("quarkus.http-signatures.keys.hook.location", "keys/hmac.jwk")
            .overrideConfigKey("quarkus.http-signatures.keys.hook.algorithm", "hmac-sha256")
            .overrideConfigKey("quarkus.http-signatures.clients.partner.key-id", "hook")
            .overrideConfigKey("quarkus.http-signatures.verify.schemes", "cavage")
            .overrideConfigKey("quarkus.http-signatures.sign.preferred-scheme", "cavage");

    @Inject
    StaticKeys keys;

    @Inject
    KeyResolver resolver;

    @Inject
    SigningKeyProvider provider;

    @Inject
    NonceStore nonces;

    @Inject
    HttpSignaturesConfig cfg;

    @Test
    void loadsRsaSigningAndVerificationKeys() {
        SigningKey s = keys.signing("rsa").orElseThrow();
        VerificationKey v = keys.verification("rsa").orElseThrow();
        assertInstanceOf(PrivateKey.class, s.key());
        assertInstanceOf(PublicKey.class, v.key());
        assertEquals(KeyType.RSA, s.keyType());
        assertEquals(Algorithm.RSA_V1_5_SHA256, s.algorithm());
    }

    @Test
    void loadsEd25519Pair() {
        assertEquals(KeyType.ED25519, keys.signing("ed").orElseThrow().keyType());
        assertEquals(KeyType.ED25519, keys.verification("ed").orElseThrow().keyType());
        assertEquals(Algorithm.ED25519, keys.signing("ed").orElseThrow().algorithm());
    }

    @Test
    void loadsHmacSecret() {
        assertInstanceOf(SecretKey.class, keys.signing("hook").orElseThrow().key());
        assertInstanceOf(SecretKey.class, keys.verification("hook").orElseThrow().key());
        assertEquals(Optional.of(Algorithm.HMAC_SHA256), keys.verification("hook").orElseThrow().algorithm());
    }

    @Test
    void unknownIdIsEmpty() {
        assertTrue(keys.signing("nope").isEmpty());
        assertTrue(resolver.resolve("nope").isEmpty());
    }

    @Test
    void defaultResolverFindsConfiguredKey() {
        assertEquals("ed", resolver.resolve("ed").orElseThrow().keyId());
    }

    @Test
    void defaultProviderPrefersClientKeyId() {
        assertEquals("hook", provider.select(URI.create("https://partner.example/hook"), Optional.of("partner")).orElseThrow().keyId());
    }

    @Test
    void defaultProviderWithoutClientAndSeveralKeysIsEmpty() {
        assertTrue(provider.select(URI.create("https://partner.example/hook"), Optional.empty()).isEmpty());
        assertTrue(provider.select(URI.create("https://partner.example/hook"), Optional.of("unknown-client")).isEmpty());
    }

    @Test
    void nonceStoreRejectsSecondUse() {
        Instant in = Instant.now().plusSeconds(60);
        assertTrue(nonces.firstUse("n1", in));
        assertFalse(nonces.firstUse("n1", in));
        assertTrue(nonces.firstUse("n2", in));
    }

    @Test
    void enumConfigValuesAreLowercaseIds() {
        assertEquals(java.util.List.of(Scheme.CAVAGE), cfg.verify().schemes());
        assertEquals(Scheme.CAVAGE, cfg.sign().preferredScheme());
        assertEquals(Optional.of(Algorithm.HMAC_SHA256), cfg.keys().get("hook").algorithm());
    }
}
