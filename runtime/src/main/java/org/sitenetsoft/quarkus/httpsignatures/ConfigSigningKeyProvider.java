package org.sitenetsoft.quarkus.httpsignatures;

import java.net.URI;
import java.util.Optional;
import java.util.Set;

import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.sitenetsoft.httpsignatures.SigningKey;

/**
 * Config-based provider (priority 0, so providers with a higher {@code @Priority} are asked first): the client's configured {@code key-id}, else the key named {@code default}, else the only key.
 * The {@code default}/only-key fallback applies only without a client name or for a client configured under
 * {@code quarkus.http-signatures.clients."<name>"}; any other client name belongs to another provider and gets nothing here,
 * so a request meant for an application key (for example an ActivityPub actor's) is never signed with a config key.
 */
@Priority(0)
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
            if (client == null) {
                return Optional.empty();
            }
            if (client.keyId().isPresent()) {
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
