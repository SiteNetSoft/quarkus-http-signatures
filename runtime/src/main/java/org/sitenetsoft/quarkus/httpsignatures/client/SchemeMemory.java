package org.sitenetsoft.quarkus.httpsignatures.client;

import java.time.Duration;
import java.util.Locale;
import java.util.Optional;

import jakarta.enterprise.context.ApplicationScoped;

import org.sitenetsoft.httpsignatures.Scheme;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

/**
 * Remembers, per host, which signature scheme a remote server accepted ("double knocking").
 */
@ApplicationScoped
public class SchemeMemory {

    private final Cache<String, Scheme> schemes = Caffeine.newBuilder().maximumSize(10_000).expireAfterWrite(Duration.ofHours(24)).build();

    public Optional<Scheme> preferredFor(String host) {
        return Optional.ofNullable(schemes.getIfPresent(key(host)));
    }

    public void remember(String host, Scheme scheme) {
        schemes.put(key(host), scheme);
    }

    public void forget(String host) {
        schemes.invalidate(key(host));
    }

    private static String key(String host) {
        return host == null ? "" : host.toLowerCase(Locale.ROOT);
    }
}
