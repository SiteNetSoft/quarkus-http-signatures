package org.sitenetsoft.quarkus.httpsignatures.vertx;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;
import org.sitenetsoft.httpsignatures.HttpMessageView;
import org.sitenetsoft.httpsignatures.HttpSignatureException;
import org.sitenetsoft.httpsignatures.HttpSignatureException.Reason;
import org.sitenetsoft.httpsignatures.HttpVerifier;
import org.sitenetsoft.httpsignatures.VerificationPolicy;
import org.sitenetsoft.httpsignatures.VerificationResult;
import org.sitenetsoft.quarkus.httpsignatures.CachingKeyResolver;
import org.sitenetsoft.quarkus.httpsignatures.HttpSignaturesConfig;
import org.sitenetsoft.quarkus.httpsignatures.VerificationPolicies;

import io.quarkus.runtime.LaunchMode;
import io.smallrye.mutiny.Uni;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.ext.web.RoutingContext;

/**
 * Shared by the Vert.x path handler and the Quarkus Security mechanism: buffers the body when needed, verifies on a
 * worker thread (key resolvers may do I/O), and on a signature failure drops the cached key and retries once, which
 * covers key rotation.
 */
@ApplicationScoped
public class RequestVerifier {

    private static final Logger LOG = Logger.getLogger("org.sitenetsoft.quarkus.httpsignatures");
    public static final String RESULT_KEY = "org.sitenetsoft.quarkus.httpsignatures.result";

    private final Vertx vertx;
    private final VerificationPolicies policies;
    private final CachingKeyResolver keys;
    private final long maxBodySize;
    private final HttpVerifier verifier = new HttpVerifier();

    @Inject
    public RequestVerifier(Vertx vertx, VerificationPolicies policies, CachingKeyResolver keys, HttpSignaturesConfig config) {
        this.vertx = vertx;
        this.policies = policies;
        this.keys = keys;
        this.maxBodySize = config.verify().maxBodySize().asLongValue();
    }

    /**
     * The signed request body is larger than {@code quarkus.http-signatures.verify.max-body-size}.
     */
    public static final class BodyTooLargeException extends RuntimeException {
        public BodyTooLargeException(long limit) {
            super("Signed request body exceeds " + limit + " bytes");
        }
    }

    public static boolean hasSignature(RoutingContext ctx) {
        return ctx.request().headers().contains("Signature");
    }

    /**
     * Verifies the current request; fails with {@link HttpSignatureException}.
     */
    public Uni<VerificationResult> verify(RoutingContext ctx) {
        VerificationResult existing = ctx.get(RESULT_KEY);
        if (existing != null) {
            return Uni.createFrom().item(existing);
        }
        return body(ctx, maxBodySize).chain(body -> {
            HttpMessageView msg = VertxMessageView.of(ctx, body);
            VerificationPolicy policy = policies.current();
            return Uni.createFrom().completionStage(vertx.executeBlocking(() -> verifyWithRetry(msg, policy), false).toCompletionStage());
        }).invoke(result -> ctx.put(RESULT_KEY, result));
    }

    public VerificationResult verifyWithRetry(HttpMessageView msg, VerificationPolicy policy) {
        try {
            return verifier.verify(msg, policy);
        } catch (HttpSignatureException first) {
            if (first.reason() == Reason.INVALID_SIGNATURE || first.reason() == Reason.ALGORITHM_KEY_MISMATCH) {
                keyId(msg).ifPresent(keys::invalidate);
                try {
                    return verifier.verify(msg, policy);
                } catch (HttpSignatureException second) {
                    debugFailure(msg, second);
                    throw second;
                }
            }
            debugFailure(msg, first);
            throw first;
        }
    }

    private static java.util.Optional<String> keyId(HttpMessageView msg) {
        try {
            if (HttpVerifier.detect(msg) == org.sitenetsoft.httpsignatures.Scheme.CAVAGE) {
                return java.util.Optional.of(org.sitenetsoft.httpsignatures.CavageSignature.parse(msg.headers().combined("Signature")).keyId());
            }
            var dict = org.sitenetsoft.httpsignatures.StructuredFields.parseDictionary(msg.headers().combined("Signature-Input"));
            for (Object v : dict.values()) {
                if (v instanceof org.sitenetsoft.httpsignatures.StructuredFields.InnerList l && l.params().get("keyid") instanceof String s) {
                    return java.util.Optional.of(s);
                }
            }
        } catch (RuntimeException ignored) {
            // malformed: nothing to invalidate
        }
        return java.util.Optional.empty();
    }

    private static void debugFailure(HttpMessageView msg, HttpSignatureException e) {
        if (LaunchMode.current().isDevOrTest() && LOG.isDebugEnabled()) {
            LOG.debugf("Signature verification failed (%s): %s%nSignature base:%n%s", e.reason(), e.getMessage(),
                    HttpVerifier.signatureBase(msg).orElse("<unavailable>"));
        } else {
            LOG.debugf("Signature verification failed: %s", e.reason());
        }
    }

    /**
     * The request body, buffered once (bounded by {@code maxBodySize}) and left on the context for later handlers
     * (Quarkus REST reads {@code ctx.getBody()} when it is already present). Fails with {@link BodyTooLargeException}.
     */
    public static Uni<byte[]> body(RoutingContext ctx, long maxBodySize) {
        Buffer existing = ctx.getBody();
        if (existing != null) {
            return Uni.createFrom().item(existing.getBytes());
        }
        String contentLength = ctx.request().getHeader("Content-Length");
        if (!shouldReadBody(ctx.request().method().name(), contentLength, ctx.request().getHeader("Transfer-Encoding"))) {
            return Uni.createFrom().item((byte[]) null);
        }
        if (contentLength != null) {
            try {
                if (Long.parseLong(contentLength.strip()) > maxBodySize) {
                    return Uni.createFrom().failure(new BodyTooLargeException(maxBodySize));
                }
            } catch (NumberFormatException ignored) {
                // the streamed limit below still applies
            }
        }
        io.vertx.core.Promise<Buffer> promise = io.vertx.core.Promise.promise();
        Buffer acc = Buffer.buffer();
        ctx.request().handler(chunk -> {
            if (acc.length() + chunk.length() > maxBodySize) {
                promise.tryFail(new BodyTooLargeException(maxBodySize));
                return;
            }
            acc.appendBuffer(chunk);
        });
        ctx.request().endHandler(v -> promise.tryComplete(acc));
        ctx.request().exceptionHandler(promise::tryFail);
        // Quarkus pauses the request before handlers run; the stream has to flow again
        ctx.request().resume();
        return Uni.createFrom().completionStage(promise.future().toCompletionStage()).map(buf -> {
            ctx.setBody(buf);
            return buf.getBytes();
        });
    }

    /**
     * Whether a request may carry a body worth digest-checking. HTTP/2 requests have neither Content-Length nor
     * Transfer-Encoding, so body-capable methods are always read (an absent body just yields no bytes).
     */
    static boolean shouldReadBody(String method, String contentLength, String transferEncoding) {
        if (contentLength != null) {
            try {
                return Long.parseLong(contentLength.strip()) > 0;
            } catch (NumberFormatException e) {
                return true;
            }
        }
        if (transferEncoding != null && transferEncoding.toLowerCase(java.util.Locale.ROOT).contains("chunked")) {
            return true;
        }
        return switch (method.toUpperCase(java.util.Locale.ROOT)) {
            case "GET", "HEAD", "OPTIONS", "TRACE", "DELETE" -> false;
            default -> true;
        };
    }
}
