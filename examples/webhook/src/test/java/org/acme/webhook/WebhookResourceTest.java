package org.acme.webhook;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.sitenetsoft.quarkus.httpsignatures.client.SigningHttpClient;

import io.quarkus.test.junit.QuarkusTest;

/**
 * The receiver and the sender share the configured HMAC secret; the sender here is the extension's own
 * {@code java.net.http} helper, which signs with the only configured key.
 */
@QuarkusTest
class WebhookResourceTest {

    static final String EVENT = "{\"event\":\"invoice.paid\",\"id\":42}";

    @Inject
    SigningHttpClient signingClient;

    @Test
    void signedDeliveryIsAccepted() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:8081/webhook"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(EVENT)).build();
        HttpResponse<byte[]> response = signingClient.send(HttpClient.newHttpClient(), request,
                EVENT.getBytes(StandardCharsets.UTF_8), Optional.empty());
        assertEquals(200, response.statusCode(), new String(response.body(), StandardCharsets.UTF_8));
        assertEquals("accepted from partner", new String(response.body(), StandardCharsets.UTF_8));
    }

    @Test
    void unsignedDeliveryIsRejected() {
        given().contentType("application/json").body(EVENT).when().post("/webhook").then().statusCode(401);
    }

    @Test
    void tamperedDeliveryIsRejected() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:8081/webhook"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(EVENT)).build();
        HttpRequest signed = signingClient.signed(request, EVENT.getBytes(StandardCharsets.UTF_8), Optional.empty(),
                org.sitenetsoft.httpsignatures.Scheme.RFC9421);
        HttpRequest tampered = HttpRequest.newBuilder(signed, (n, v) -> true)
                .POST(HttpRequest.BodyPublishers.ofString("{\"event\":\"invoice.refunded\"}")).build();
        HttpResponse<String> response = HttpClient.newHttpClient().send(tampered, HttpResponse.BodyHandlers.ofString());
        assertEquals(401, response.statusCode());
    }

    @Test
    void receivedListIsOpen() {
        given().when().get("/webhook").then().statusCode(200);
    }
}
