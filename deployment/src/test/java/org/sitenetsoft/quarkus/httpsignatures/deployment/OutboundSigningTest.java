package org.sitenetsoft.quarkus.httpsignatures.deployment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;

import org.eclipse.microprofile.rest.client.RestClientBuilder;
import org.eclipse.microprofile.rest.client.annotation.RegisterProvider;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.sitenetsoft.httpsignatures.Scheme;
import org.sitenetsoft.quarkus.httpsignatures.client.HttpSignatureClientFilter;
import org.sitenetsoft.quarkus.httpsignatures.client.SchemeMemory;
import org.sitenetsoft.quarkus.httpsignatures.client.SignRequests;
import org.sitenetsoft.quarkus.httpsignatures.client.SigningHttpClient;
import org.sitenetsoft.quarkus.httpsignatures.client.VertxRequestSigner;

import io.quarkus.test.QuarkusUnitTest;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.ext.web.client.WebClient;

public class OutboundSigningTest {

    static final VerifyingServer server = new VerifyingServer();
    static final String BODY = "{\"type\":\"Create\"}";

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class)
                    .addClasses(TestSigning.class, VerifyingServer.class, Hooks.class).addAsResource("keys/ed25519.pem"))
            .overrideConfigKey("quarkus.http-signatures.keys.k1.location", "keys/ed25519.pem");

    @AfterAll
    static void stop() {
        server.stop();
    }

    /**
     * Built programmatically below: QuarkusUnitTest reloads this class in its own classloader, so a port captured
     * in config would point at a different {@link VerifyingServer} instance than {@link #url(String)}.
     */
    @RegisterProvider(HttpSignatureClientFilter.class)
    @SignRequests
    @Path("/")
    public interface Hooks {
        @POST
        @Path("/inbox")
        String post(String body);

        @GET
        @Path("/status")
        String get();
    }

    @Inject
    SigningHttpClient signingClient;

    @Inject
    VertxRequestSigner vertxSigner;

    @Inject
    SchemeMemory memory;

    @Inject
    Vertx vertx;

    Hooks hooks;

    URI url(String path) {
        return URI.create("http://127.0.0.1:" + server.port() + path);
    }

    @BeforeEach
    void reset() {
        server.cavageOnly(false);
        memory.forget("127.0.0.1");
        hooks = RestClientBuilder.newBuilder().baseUri(url("/")).build(Hooks.class);
    }

    @Test
    void javaNetHelperSignsRfc9421() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(url("/inbox")).header("Content-Type", "application/activity+json")
                .POST(HttpRequest.BodyPublishers.ofString(BODY)).build();
        HttpResponse<byte[]> r = signingClient.send(HttpClient.newHttpClient(), request, BODY.getBytes(StandardCharsets.UTF_8), Optional.empty());
        assertEquals(200, r.statusCode());
        assertEquals("scheme=rfc9421 key=k1 body=" + BODY.length(), new String(r.body(), StandardCharsets.UTF_8));
    }

    @Test
    void javaNetHelperFallsBackToCavageOnceAndRemembers() throws Exception {
        server.cavageOnly(true);
        int before = server.requests();
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder(url("/inbox")).POST(HttpRequest.BodyPublishers.ofString(BODY)).build();
        HttpResponse<byte[]> first = signingClient.send(client, request, BODY.getBytes(StandardCharsets.UTF_8), Optional.empty());
        assertEquals(200, first.statusCode(), new String(first.body(), StandardCharsets.UTF_8));
        assertTrue(new String(first.body(), StandardCharsets.UTF_8).startsWith("scheme=cavage"));
        assertEquals(2, server.requests() - before, "one knock per scheme");

        HttpResponse<byte[]> second = signingClient.send(client, request, BODY.getBytes(StandardCharsets.UTF_8), Optional.empty());
        assertEquals(200, second.statusCode());
        assertEquals(3, server.requests() - before, "the remembered scheme is used directly");
        assertEquals(Scheme.CAVAGE, memory.preferredFor("127.0.0.1").orElseThrow());
    }

    @Test
    void javaNetHelperGetWithoutBody() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(url("/status")).GET().build();
        HttpResponse<byte[]> r = signingClient.send(HttpClient.newHttpClient(), request, null, Optional.empty());
        assertEquals(200, r.statusCode());
        assertEquals("scheme=rfc9421 key=k1 body=0", new String(r.body(), StandardCharsets.UTF_8));
    }

    @Test
    void vertxSignerProducesVerifiableHeaders() {
        WebClient client = WebClient.create(vertx);
        try {
            byte[] body = BODY.getBytes(StandardCharsets.UTF_8);
            var request = client.postAbs(url("/inbox").toString()).putHeader("Content-Type", "application/activity+json");
            vertxSigner.sign(request, url("/inbox"), body, Optional.empty(), Scheme.CAVAGE);
            var response = request.sendBuffer(Buffer.buffer(body)).toCompletionStage().toCompletableFuture().join();
            assertEquals(200, response.statusCode(), response.bodyAsString());
            assertEquals("scheme=cavage key=k1 body=" + body.length, response.bodyAsString());
        } finally {
            client.close();
        }
    }

    @Test
    void restClientFilterSignsPostWithDigest() {
        assertEquals("scheme=rfc9421 key=k1 body=" + BODY.length(), hooks.post(BODY));
    }

    @Test
    void restClientFilterSignsGet() {
        assertEquals("scheme=rfc9421 key=k1 body=0", hooks.get());
    }

    @Test
    void restClientFilterLearnsFromRejection() {
        server.cavageOnly(true);
        try {
            hooks.post(BODY);
        } catch (RuntimeException expected) {
            // the first call is rejected; the filter remembers that this host wants Cavage
        }
        assertEquals(Scheme.CAVAGE, memory.preferredFor("127.0.0.1").orElseThrow());
        assertEquals("scheme=cavage key=k1 body=" + BODY.length(), hooks.post(BODY));
    }
}
