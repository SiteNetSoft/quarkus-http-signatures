package org.acme.webhook;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;

import org.sitenetsoft.quarkus.httpsignatures.SignatureContext;
import org.sitenetsoft.quarkus.httpsignatures.rest.SignatureRequired;

/**
 * A webhook receiver: every delivery must carry a valid HMAC signature over the method, target and body.
 */
@Path("/webhook")
public class WebhookResource {

    private final List<String> received = new CopyOnWriteArrayList<>();

    @Inject
    SignatureContext signature;

    @POST
    @SignatureRequired(components = { "@method", "@target-uri", "content-digest" })
    public String receive(String body) {
        received.add(body);
        return "accepted from " + signature.result().orElseThrow().keyId();
    }

    @GET
    public List<String> received() {
        return received;
    }
}
