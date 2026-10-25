package org.sitenetsoft.quarkus.httpsignatures;

import java.util.Optional;

import org.sitenetsoft.httpsignatures.VerificationKey;

import io.smallrye.mutiny.Uni;

/**
 * Mutiny form of {@link org.sitenetsoft.httpsignatures.KeyResolver}.
 */
public interface ReactiveKeyResolver {

    Uni<Optional<VerificationKey>> resolve(String keyId);
}
