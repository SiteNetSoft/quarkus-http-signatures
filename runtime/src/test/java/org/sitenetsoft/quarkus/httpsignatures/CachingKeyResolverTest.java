package org.sitenetsoft.quarkus.httpsignatures;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.sitenetsoft.httpsignatures.KeyResolver;
import org.sitenetsoft.httpsignatures.VerificationKey;

class CachingKeyResolverTest {

    @Test
    void negativeResultsAreNotCached() throws Exception {
        AtomicReference<Optional<VerificationKey>> answer = new AtomicReference<>(Optional.empty());
        AtomicInteger calls = new AtomicInteger();
        KeyResolver backend = id -> {
            calls.incrementAndGet();
            return answer.get();
        };
        CachingKeyResolver cache = new CachingKeyResolver(List.of(backend), List.of(), Duration.ofHours(1));
        assertTrue(cache.resolve("k").isEmpty());
        assertTrue(cache.resolve("k").isEmpty());
        assertEquals(2, calls.get(), "a miss is asked again");

        var key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic();
        answer.set(Optional.of(new VerificationKey("k", Optional.empty(), key)));
        assertTrue(cache.resolve("k").isPresent());
        assertTrue(cache.resolve("k").isPresent());
        assertEquals(3, calls.get(), "a hit is cached");
    }
}
