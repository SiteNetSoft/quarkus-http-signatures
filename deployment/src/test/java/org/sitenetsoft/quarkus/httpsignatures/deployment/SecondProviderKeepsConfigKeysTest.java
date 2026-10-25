package org.sitenetsoft.quarkus.httpsignatures.deployment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Optional;

import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.sitenetsoft.httpsignatures.Algorithm;
import org.sitenetsoft.httpsignatures.KeyResolver;
import org.sitenetsoft.httpsignatures.Keys;
import org.sitenetsoft.httpsignatures.SigningKey;
import org.sitenetsoft.httpsignatures.VerificationKey;
import org.sitenetsoft.quarkus.httpsignatures.CachingKeyResolver;
import org.sitenetsoft.quarkus.httpsignatures.SigningKeyProvider;
import org.sitenetsoft.quarkus.httpsignatures.client.RequestSigner;

import io.quarkus.test.QuarkusUnitTest;

/** An application-provided provider/resolver must not switch off the config-based ones. */
public class SecondProviderKeepsConfigKeysTest {

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class)
                    .addClasses(OtherProvider.class, OtherResolver.class)
                    .addAsResource("keys/ed25519.pem"))
            .overrideConfigKey("quarkus.http-signatures.keys.k1.location", "keys/ed25519.pem");

    @Inject
    RequestSigner requestSigner;

    @Inject
    CachingKeyResolver cachingKeyResolver;

    @Test
    void configKeyStillUsedWithoutClientName() {
        assertEquals("k1", requestSigner.keyFor(URI.create("https://x"), Optional.empty()).keyId());
    }

    @Test
    void appProviderUsedForItsClient() {
        assertEquals("other-key", requestSigner.keyFor(URI.create("https://x"), Optional.of("other")).keyId());
    }

    @Test
    void unknownClientNameDoesNotFallBackToConfigKey() {
        // a client name nobody configured (e.g. activitypub:<keyId> after the actor was deleted) must not be
        // signed with the application's only config key under that key's id
        assertThrows(IllegalStateException.class,
                () -> requestSigner.keyFor(URI.create("https://x"), Optional.of("activitypub:https://x/users/a#main-key")));
    }

    @Test
    void bothResolversAnswer() {
        assertTrue(cachingKeyResolver.resolve("k1").isPresent());
        assertTrue(cachingKeyResolver.resolve("other-key").isPresent());
    }

    static List<Key> pem() {
        try (InputStream in = SecondProviderKeepsConfigKeysTest.class.getClassLoader().getResourceAsStream("keys/ed25519.pem")) {
            return Keys.parsePemAll(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @ApplicationScoped
    @Priority(10)
    public static class OtherProvider implements SigningKeyProvider {
        @Override
        public Optional<SigningKey> select(URI target, Optional<String> clientName) {
            if (clientName.filter("other"::equals).isEmpty()) {
                return Optional.empty();
            }
            Key priv = pem().stream().filter(PrivateKey.class::isInstance).findFirst().orElseThrow();
            return Optional.of(new SigningKey("other-key", Algorithm.ED25519, priv));
        }
    }

    @ApplicationScoped
    @Priority(10)
    public static class OtherResolver implements KeyResolver {
        @Override
        public Optional<VerificationKey> resolve(String keyId) {
            if (!"other-key".equals(keyId)) {
                return Optional.empty();
            }
            Key pub = pem().stream().filter(PublicKey.class::isInstance).findFirst().orElseThrow();
            return Optional.of(new VerificationKey("other-key", Optional.of(Algorithm.ED25519), pub));
        }
    }
}
