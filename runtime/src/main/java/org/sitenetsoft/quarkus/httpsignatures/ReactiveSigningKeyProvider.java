package org.sitenetsoft.quarkus.httpsignatures;

import java.net.URI;
import java.util.Optional;

import org.sitenetsoft.httpsignatures.SigningKey;

import io.smallrye.mutiny.Uni;

public interface ReactiveSigningKeyProvider {

    Uni<Optional<SigningKey>> select(URI target, Optional<String> clientName);
}
