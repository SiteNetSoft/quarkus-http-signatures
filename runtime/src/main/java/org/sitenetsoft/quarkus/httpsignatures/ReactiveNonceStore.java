package org.sitenetsoft.quarkus.httpsignatures;

import java.time.Instant;

import io.smallrye.mutiny.Uni;

public interface ReactiveNonceStore {

    Uni<Boolean> firstUse(String nonce, Instant expires);
}
