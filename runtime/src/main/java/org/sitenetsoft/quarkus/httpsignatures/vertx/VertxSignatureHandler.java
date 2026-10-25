package org.sitenetsoft.quarkus.httpsignatures.vertx;

import java.util.List;
import java.util.regex.Pattern;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;
import org.sitenetsoft.httpsignatures.HttpSignatureException;
import org.sitenetsoft.quarkus.httpsignatures.HttpSignaturesConfig;

import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

/**
 * Requires a valid signature on the paths listed in {@code quarkus.http-signatures.verify.paths}. Patterns follow
 * Vert.x conventions: {@code /inbox/*} matches a prefix, otherwise the path must match exactly. Failure answers 401
 * with no detail; a success stores the {@link org.sitenetsoft.httpsignatures.VerificationResult} under
 * {@link #RESULT_KEY}.
 */
@ApplicationScoped
public class VertxSignatureHandler implements Handler<RoutingContext> {

    private static final Logger LOG = Logger.getLogger("org.sitenetsoft.quarkus.httpsignatures");
    public static final String RESULT_KEY = RequestVerifier.RESULT_KEY;

    private final RequestVerifier verifier;
    private final List<Pattern> patterns;

    @Inject
    public VertxSignatureHandler(RequestVerifier verifier, HttpSignaturesConfig config) {
        this.verifier = verifier;
        this.patterns = config.verify().paths().orElse(List.of()).stream().map(VertxSignatureHandler::compile).toList();
    }

    static Pattern compile(String pattern) {
        StringBuilder sb = new StringBuilder("^");
        for (char c : pattern.strip().toCharArray()) {
            if (c == '*') {
                sb.append(".*");
            } else {
                sb.append(Pattern.quote(String.valueOf(c)));
            }
        }
        return Pattern.compile(sb.append('$').toString());
    }

    boolean matches(String path) {
        return patterns.stream().anyMatch(p -> p.matcher(path).matches());
    }

    @Override
    public void handle(RoutingContext ctx) {
        if (patterns.isEmpty() || !matches(ctx.normalizedPath())) {
            ctx.next();
            return;
        }
        if (!RequestVerifier.hasSignature(ctx)) {
            reject(ctx);
            return;
        }
        verifier.verify(ctx).subscribe().with(result -> ctx.next(), failure -> {
            if (failure instanceof RequestVerifier.BodyTooLargeException) {
                ctx.response().setStatusCode(413).end();
                return;
            }
            if (!(failure instanceof HttpSignatureException)) {
                LOG.debug("Signature verification error", failure);
            }
            reject(ctx);
        });
    }

    private static void reject(RoutingContext ctx) {
        ctx.response().setStatusCode(401).putHeader("WWW-Authenticate", "Signature").end();
    }
}
