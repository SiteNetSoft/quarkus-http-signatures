package org.sitenetsoft.httpsignatures;

import java.util.Optional;

/**
 * Maps a key id to a verification key. Apps implement this: from a database, config, or by fetching an
 * ActivityPub actor's public key.
 */
@FunctionalInterface
public interface KeyResolver {

    Optional<VerificationKey> resolve(String keyId);
}
