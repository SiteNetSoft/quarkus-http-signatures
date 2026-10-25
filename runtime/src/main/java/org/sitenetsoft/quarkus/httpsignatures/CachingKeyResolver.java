package org.sitenetsoft.quarkus.httpsignatures;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.sitenetsoft.httpsignatures.KeyResolver;
import org.sitenetsoft.httpsignatures.VerificationKey;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.quarkus.arc.All;

/**
 * Runs every {@link KeyResolver} and {@link ReactiveKeyResolver} bean (highest priority first) and caches the result
 * for {@code quarkus.http-signatures.key-cache.ttl}. {@link #invalidate(String)} supports the refetch-once rule.
 * Not itself a {@code KeyResolver} bean, so the {@code @DefaultBean} resolver stays active.
 */
@ApplicationScoped
public class CachingKeyResolver {

    private final List<KeyResolver> resolvers;
    private final List<ReactiveKeyResolver> reactiveResolvers;
    private final Cache<String, Optional<VerificationKey>> cache;

    @Inject
    public CachingKeyResolver(@All List<KeyResolver> resolvers, @All List<ReactiveKeyResolver> reactiveResolvers,
            HttpSignaturesConfig config) {
        this.resolvers = resolvers;
        this.reactiveResolvers = reactiveResolvers;
        this.cache = Caffeine.newBuilder().maximumSize(10_000).expireAfterWrite(config.keyCache().ttl()).build();
    }

    public Optional<VerificationKey> resolve(String keyId) {
        return cache.get(keyId, this::lookup);
    }

    /**
     * This cache as a {@link KeyResolver} for a {@link org.sitenetsoft.httpsignatures.VerificationPolicy}.
     */
    public KeyResolver asResolver() {
        return this::resolve;
    }

    public void invalidate(String keyId) {
        cache.invalidate(keyId);
    }

    private Optional<VerificationKey> lookup(String keyId) {
        for (KeyResolver r : resolvers) {
            Optional<VerificationKey> k = r.resolve(keyId);
            if (k.isPresent()) {
                return k;
            }
        }
        for (ReactiveKeyResolver r : reactiveResolvers) {
            Optional<VerificationKey> k = r.resolve(keyId).await().atMost(Duration.ofSeconds(30));
            if (k.isPresent()) {
                return k;
            }
        }
        return Optional.empty();
    }
}
