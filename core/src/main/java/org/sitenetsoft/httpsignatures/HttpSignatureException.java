package org.sitenetsoft.httpsignatures;

/**
 * A signature could not be produced or verified. {@link #reason()} is safe to expose in logs; the message never
 * contains key material or signature values.
 */
public class HttpSignatureException extends RuntimeException {

    public enum Reason {
        MALFORMED,
        UNSUPPORTED_ALGORITHM,
        UNKNOWN_KEY,
        ALGORITHM_KEY_MISMATCH,
        MISSING_COMPONENT,
        DIGEST_MISMATCH,
        MISSING_DIGEST,
        EXPIRED,
        STALE,
        FUTURE_CREATED,
        INVALID_SIGNATURE,
        REPLAY,
        SCHEME_NOT_ALLOWED
    }

    private final Reason reason;

    public HttpSignatureException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public HttpSignatureException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
