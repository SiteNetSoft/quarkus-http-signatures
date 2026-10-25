package org.sitenetsoft.quarkus.httpsignatures;

import org.sitenetsoft.httpsignatures.NonceCheck;

/**
 * Replay protection store. The default is in-memory; apps running several instances provide a shared one.
 */
public interface NonceStore extends NonceCheck {
}
