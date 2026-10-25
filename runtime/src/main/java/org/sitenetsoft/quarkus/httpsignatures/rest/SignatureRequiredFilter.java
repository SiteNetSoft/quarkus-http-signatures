package org.sitenetsoft.quarkus.httpsignatures.rest;

import java.lang.reflect.Method;

import jakarta.inject.Inject;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.server.ServerRequestFilter;
import org.sitenetsoft.httpsignatures.Component;
import org.sitenetsoft.httpsignatures.VerificationResult;
import org.sitenetsoft.quarkus.httpsignatures.vertx.RequestVerifier;

import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

/**
 * Enforces {@link SignatureRequired}. Reuses a verification already done by Quarkus Security or the Vert.x path
 * handler, and verifies itself otherwise.
 */
public class SignatureRequiredFilter {

    private static final Logger LOG = Logger.getLogger("org.sitenetsoft.quarkus.httpsignatures");

    @Inject
    RequestVerifier verifier;

    @ServerRequestFilter
    public Uni<Response> filter(ResourceInfo info, RoutingContext ctx) {
        SignatureRequired required = find(info);
        if (required == null) {
            return Uni.createFrom().nullItem();
        }
        if (!RequestVerifier.hasSignature(ctx)) {
            return Uni.createFrom().item(unauthorized());
        }
        return verifier.verify(ctx)
                .map(result -> coversAll(result, required.components()) ? null : unauthorized())
                .onFailure().recoverWithItem(t -> {
                    LOG.debugf("@SignatureRequired rejected request: %s", t.getMessage());
                    return unauthorized();
                });
    }

    static SignatureRequired find(ResourceInfo info) {
        Method m = info.getResourceMethod();
        if (m != null && m.isAnnotationPresent(SignatureRequired.class)) {
            return m.getAnnotation(SignatureRequired.class);
        }
        Class<?> c = info.getResourceClass();
        return c == null ? null : c.getAnnotation(SignatureRequired.class);
    }

    static boolean coversAll(VerificationResult result, String[] components) {
        for (String c : components) {
            if (!result.covers(Component.of(c).name())) {
                LOG.debugf("@SignatureRequired: signature does not cover %s", c);
                return false;
            }
        }
        return true;
    }

    private static Response unauthorized() {
        return Response.status(Response.Status.UNAUTHORIZED).header("WWW-Authenticate", "Signature").build();
    }
}
