package org.sitenetsoft.quarkus.httpsignatures;

import java.net.URI;
import java.util.Optional;
import java.util.Set;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.sitenetsoft.httpsignatures.SigningKey;

import io.quarkus.arc.DefaultBean;

/**
 * Default provider: the client's configured {@code key-id}, else the key named {@code default}, else the only key.
 */
@DefaultBean
@ApplicationScoped
public class ConfigSigningKeyProvider implements SigningKeyProvider {

    public static final String DEFAULT_KEY_ID = "default";

    private final StaticKeys keys;
    private final HttpSignaturesConfig config;

    @Inject
    public ConfigSigningKeyProvider(StaticKeys keys, HttpSignaturesConfig config) {
        this.keys = keys;
        this.config = config;
    }

    @Override
    public Optional<SigningKey> select(URI target, Optional<String> clientName) {
        if (clientName.isPresent()) {
            HttpSignaturesConfig.ClientConfig client = config.clients().get(clientName.get());
            if (client != null && client.keyId().isPresent()) {
                return keys.signing(client.keyId().get());
            }
        }
        Set<String> ids = keys.ids();
        if (ids.contains(DEFAULT_KEY_ID)) {
            return keys.signing(DEFAULT_KEY_ID);
        }
        if (ids.size() == 1) {
            return keys.signing(ids.iterator().next());
        }
        return Optional.empty();
    }
}
