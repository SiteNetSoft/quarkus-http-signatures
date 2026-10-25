package org.sitenetsoft.quarkus.httpsignatures.security;

import java.util.Set;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.sitenetsoft.httpsignatures.HttpSignatureException;
import org.sitenetsoft.quarkus.httpsignatures.vertx.RequestVerifier;

import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

/**
 * Quarkus Security integration: a request carrying a {@code Signature} header is authenticated by verifying it, so
 * {@code @Authenticated}, {@code @RolesAllowed} and HTTP permission policies work unchanged. Requests without a
 * signature are left to other mechanisms.
 */
@ApplicationScoped
public class HttpSignatureAuthenticationMechanism implements HttpAuthenticationMechanism {

    private final RequestVerifier verifier;

    @Inject
    public HttpSignatureAuthenticationMechanism(RequestVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {
        if (!RequestVerifier.hasSignature(context)) {
            return Uni.createFrom().nullItem();
        }
        return verifier.verify(context)
                .onFailure().transform(t -> t instanceof HttpSignatureException e
                        ? new AuthenticationFailedException("HTTP signature rejected: " + e.reason())
                        : new AuthenticationFailedException("HTTP signature could not be verified", t))
                .chain(result -> {
                    HttpSignatureAuthenticationRequest request = new HttpSignatureAuthenticationRequest(result);
                    HttpSecurityUtils.setRoutingContextAttribute(request, context);
                    return identityProviderManager.authenticate(request);
                });
    }

    @Override
    public Uni<ChallengeData> getChallenge(RoutingContext context) {
        return Uni.createFrom().item(new ChallengeData(401, "WWW-Authenticate", "Signature"));
    }

    @Override
    public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
        return Set.of(HttpSignatureAuthenticationRequest.class);
    }

    @Override
    public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
        return Uni.createFrom().item(new HttpCredentialTransport(HttpCredentialTransport.Type.OTHER_HEADER, "Signature"));
    }
}
