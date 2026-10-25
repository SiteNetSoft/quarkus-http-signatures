package org.sitenetsoft.quarkus.httpsignatures.security;

import jakarta.enterprise.context.ApplicationScoped;

import org.sitenetsoft.httpsignatures.VerificationResult;

import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

/**
 * Turns a verified signature into a {@link SecurityIdentity}: the principal is the key id, the role is
 * {@code signed}, and the {@link VerificationResult} is available as the {@code http-signature} attribute.
 */
@ApplicationScoped
public class HttpSignatureIdentityProvider implements IdentityProvider<HttpSignatureAuthenticationRequest> {

    public static final String ROLE = "signed";
    public static final String ATTRIBUTE = "http-signature";

    @Override
    public Class<HttpSignatureAuthenticationRequest> getRequestType() {
        return HttpSignatureAuthenticationRequest.class;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(HttpSignatureAuthenticationRequest request, AuthenticationRequestContext context) {
        VerificationResult result = request.result();
        return Uni.createFrom().item(QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(result.keyId()))
                .addRole(ROLE)
                .addAttribute(ATTRIBUTE, result)
                .build());
    }
}
