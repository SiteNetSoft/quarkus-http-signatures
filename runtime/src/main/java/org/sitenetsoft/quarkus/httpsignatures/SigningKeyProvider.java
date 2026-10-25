package org.sitenetsoft.quarkus.httpsignatures;

import java.net.URI;
import java.util.Optional;

import org.sitenetsoft.httpsignatures.SigningKey;

/**
 * Chooses the key for an outbound request. The default reads static keys from config.
 */
public interface SigningKeyProvider {

    Optional<SigningKey> select(URI target, Optional<String> clientName);
}
