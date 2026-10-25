package org.sitenetsoft.httpsignatures;

import java.time.Instant;

/**
 * Replay protection: returns {@code true} the first time a nonce is seen, {@code false} afterwards until
 * {@code expires}.
 */
@FunctionalInterface
public interface NonceCheck {

    boolean firstUse(String nonce, Instant expires);
}
