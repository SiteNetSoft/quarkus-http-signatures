package org.sitenetsoft.quarkus.httpsignatures.security;

import org.sitenetsoft.httpsignatures.VerificationResult;

import io.quarkus.security.identity.request.BaseAuthenticationRequest;

/**
 * Carries an already verified signature to the {@link HttpSignatureIdentityProvider}.
 */
public class HttpSignatureAuthenticationRequest extends BaseAuthenticationRequest {

    private final VerificationResult result;

    public HttpSignatureAuthenticationRequest(VerificationResult result) {
        this.result = result;
    }

    public VerificationResult result() {
        return result;
    }
}
