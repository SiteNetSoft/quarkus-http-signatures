package org.sitenetsoft.quarkus.httpsignatures;

import java.util.Optional;

import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.sitenetsoft.httpsignatures.KeyResolver;
import org.sitenetsoft.httpsignatures.VerificationKey;

/**
 * Config-based resolver (priority 0): verification keys come from static config. It stays active next to your own
 * {@link KeyResolver} beans, which can fetch keys elsewhere (for example an ActivityPub actor's public key).
 */
@Priority(0)
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
