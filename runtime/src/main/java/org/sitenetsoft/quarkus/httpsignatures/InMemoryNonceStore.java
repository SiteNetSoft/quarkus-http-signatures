package org.sitenetsoft.quarkus.httpsignatures;

import java.time.Duration;
import java.time.Instant;

import jakarta.enterprise.context.ApplicationScoped;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;

import io.quarkus.arc.DefaultBean;

/**
 * Single-node replay protection: remembers each nonce until it expires.
 */
@DefaultBean
@ApplicationScoped
public class InMemoryNonceStore implements NonceStore {

    private final Cache<String, Instant> seen = Caffeine.newBuilder()
            .maximumSize(100_000)
            .expireAfter(new Expiry<String, Instant>() {
                @Override
                public long expireAfterCreate(String key, Instant expires, long currentTime) {
                    return Math.max(0, Duration.between(Instant.now(), expires).toNanos());
                }

                @Override
                public long expireAfterUpdate(String key, Instant expires, long currentTime, long currentDuration) {
                    return currentDuration;
                }

                @Override
                public long expireAfterRead(String key, Instant expires, long currentTime, long currentDuration) {
                    return currentDuration;
                }
            })
            .build();

    @Override
    public boolean firstUse(String nonce, Instant expires) {
        return seen.asMap().putIfAbsent(nonce, expires) == null;
    }
}
