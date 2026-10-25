package org.sitenetsoft.quarkus.httpsignatures;

import java.util.Optional;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;

import org.sitenetsoft.httpsignatures.VerificationResult;
import org.sitenetsoft.quarkus.httpsignatures.vertx.RequestVerifier;

import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.ext.web.RoutingContext;

/**
 * The verified signature of the current request, when there is one. Reads the result the verifier stored on the
 * Vert.x {@link RoutingContext}, so it works whether the request was verified by Quarkus Security, the path handler
 * or the {@code @SignatureRequired} filter.
 */
@RequestScoped
public class SignatureContext {

    @Inject
    CurrentVertxRequest current;

    private VerificationResult override;

    public boolean isVerified() {
        return result().isPresent();
    }

    public Optional<VerificationResult> result() {
        if (override != null) {
            return Optional.of(override);
        }
        RoutingContext ctx = current.getCurrent();
        return ctx == null ? Optional.empty() : Optional.ofNullable(ctx.get(RequestVerifier.RESULT_KEY));
    }

    public void set(VerificationResult result) {
        this.override = result;
    }
}
