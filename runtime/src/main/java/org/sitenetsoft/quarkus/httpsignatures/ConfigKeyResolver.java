package org.sitenetsoft.quarkus.httpsignatures;

import java.util.Optional;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.sitenetsoft.httpsignatures.KeyResolver;
import org.sitenetsoft.httpsignatures.VerificationKey;

import io.quarkus.arc.DefaultBean;

/**
 * Default resolver: verification keys come from static config. Provide your own {@link KeyResolver} bean to fetch
 * keys elsewhere (for example an ActivityPub actor's public key).
 */
@DefaultBean
@ApplicationScoped
public class ConfigKeyResolver implements KeyResolver {

    private final StaticKeys keys;

    @Inject
    public ConfigKeyResolver(StaticKeys keys) {
        this.keys = keys;
    }

    @Override
    public Optional<VerificationKey> resolve(String keyId) {
        return keys.verification(keyId);
    }
}
