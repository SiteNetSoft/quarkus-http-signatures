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
 * Not itself a {@code KeyResolver} bean, so the config resolver stays active.
 */
@ApplicationScoped
public class CachingKeyResolver {

    private final List<KeyResolver> resolvers;
    private final List<ReactiveKeyResolver> reactiveResolvers;
    private final Cache<String, VerificationKey> cache;

    @Inject
    public CachingKeyResolver(@All List<KeyResolver> resolvers, @All List<ReactiveKeyResolver> reactiveResolvers,
            HttpSignaturesConfig config) {
        this(resolvers, reactiveResolvers, config.keyCache().ttl());
    }

    CachingKeyResolver(List<KeyResolver> resolvers, List<ReactiveKeyResolver> reactiveResolvers, Duration ttl) {
        this.resolvers = resolvers;
        this.reactiveResolvers = reactiveResolvers;
        this.cache = Caffeine.newBuilder().maximumSize(10_000).expireAfterWrite(ttl).build();
    }

    /**
     * Only hits are cached: a miss (unknown key, or a transient failure in an app resolver) is asked again next time
     * instead of locking the key id out for the whole TTL.
     */
    public Optional<VerificationKey> resolve(String keyId) {
        VerificationKey hit = cache.getIfPresent(keyId);
        if (hit != null) {
            return Optional.of(hit);
        }
        Optional<VerificationKey> found = lookup(keyId);
        found.ifPresent(k -> cache.put(keyId, k));
        return found;
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
