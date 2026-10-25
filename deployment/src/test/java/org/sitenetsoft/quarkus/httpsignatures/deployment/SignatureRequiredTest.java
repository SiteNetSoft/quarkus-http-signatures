package org.sitenetsoft.quarkus.httpsignatures.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import jakarta.inject.Inject;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.sitenetsoft.httpsignatures.Algorithm;
import org.sitenetsoft.httpsignatures.Headers;
import org.sitenetsoft.httpsignatures.HttpMessageView;
import org.sitenetsoft.httpsignatures.HttpSigner;
import org.sitenetsoft.httpsignatures.Keys;
import org.sitenetsoft.httpsignatures.Scheme;
import org.sitenetsoft.httpsignatures.SignatureSpec;
import org.sitenetsoft.httpsignatures.SignedHeaders;
import org.sitenetsoft.httpsignatures.SigningKey;
import org.sitenetsoft.quarkus.httpsignatures.SignatureContext;
import org.sitenetsoft.quarkus.httpsignatures.rest.SignatureRequired;

import io.quarkus.test.QuarkusUnitTest;
import io.restassured.specification.RequestSpecification;

/**
 * {@code @SignatureRequired} on Quarkus REST endpoints, including the HMAC webhook case with no ActivityPub involved.
 */
public class SignatureRequiredTest {

    static final String BODY = "{\"event\":\"invoice.paid\"}";

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class).addClasses(TestSigning.class, Hooks.class)
                    .addAsResource("keys/ed25519.pem").addAsResource("keys/hmac.jwk"))
            .overrideConfigKey("quarkus.http-signatures.keys.k1.location", "keys/ed25519.pem")
            .overrideConfigKey("quarkus.http-signatures.keys.hook.location", "keys/hmac.jwk");

    @Path("/hooks")
    public static class Hooks {
        @Inject
        SignatureContext signature;

        @POST
        @Path("/strict")
        @SignatureRequired(components = { "@method", "@target-uri", "content-digest" })
        public String strict(String body) {
            return signature.result().orElseThrow().keyId() + ":" + body.length();
        }

        @POST
        @Path("/any")
        @SignatureRequired
        public String any(String body) {
            return signature.result().orElseThrow().keyId();
        }

        @POST
        @Path("/open")
        public String open(String body) {
            return signature.isVerified() ? "signed" : "unsigned";
        }
    }

    static RequestSpecification signedHmac(String url, String body) {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        URI uri = URI.create(url);
        HttpMessageView msg = HttpMessageView.of("POST", uri, Headers.of(Map.of("Host", List.of("localhost:8081"),
                "Content-Type", List.of("application/json"))), bytes);
        SigningKey key = new SigningKey("hook", Algorithm.HMAC_SHA256, Keys.parseJwk(TestSigning.resource("keys/hmac.jwk")));
        SignedHeaders signed = new HttpSigner().sign(msg, SignatureSpec.rfc9421("hook", Algorithm.HMAC_SHA256, Instant.now(), true), key);
        RequestSpecification spec = given().contentType("application/json").body(body);
        signed.headers().forEach(spec::header);
        return spec;
    }

    @Test
    void signedWithComponentsIs200() {
        RequestSpecification spec = given().body(BODY);
        TestSigning.sign(Scheme.RFC9421, "POST", "http://localhost:8081/hooks/strict", BODY).forEach(spec::header);
        spec.when().post("/hooks/strict").then().statusCode(200).body(equalTo("k1:" + BODY.length()));
    }

    @Test
    void signedWithoutRequiredComponentIs401() {
        RequestSpecification spec = given().body(BODY);
        TestSigning.sign(Scheme.RFC9421, "POST", "http://localhost:8081/hooks/strict", BODY,
                List.of("@method", "@authority", "@path", "content-digest")).forEach(spec::header);
        spec.when().post("/hooks/strict").then().statusCode(401);
    }

    @Test
    void cavageSatisfiesPlainSignatureRequired() {
        RequestSpecification spec = given().body(BODY);
        TestSigning.sign(Scheme.CAVAGE, "POST", "http://localhost:8081/hooks/any", BODY).forEach(spec::header);
        spec.when().post("/hooks/any").then().statusCode(200).body(equalTo("k1"));
    }

    @Test
    void unsignedIs401() {
        given().contentType("application/json").body(BODY).when().post("/hooks/any").then().statusCode(401);
    }

    @Test
    void hmacWebhookWorks() {
        signedHmac("http://localhost:8081/hooks/strict", BODY).when().post("/hooks/strict")
                .then().statusCode(200).body(equalTo("hook:" + BODY.length()));
    }

    @Test
    void openEndpointSeesVerificationStateWithoutRequiringIt() {
        given().contentType("application/json").body(BODY).when().post("/hooks/open").then().statusCode(200).body(equalTo("unsigned"));
        signedHmac("http://localhost:8081/hooks/open", BODY).when().post("/hooks/open").then().statusCode(200).body(equalTo("signed"));
    }
}
