package org.sitenetsoft.quarkus.httpsignatures.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

import java.util.Map;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.sitenetsoft.httpsignatures.Scheme;
import org.sitenetsoft.httpsignatures.VerificationResult;
import org.sitenetsoft.quarkus.httpsignatures.vertx.VertxSignatureHandler;

import io.quarkus.test.QuarkusUnitTest;
import io.restassured.specification.RequestSpecification;
import io.vertx.ext.web.Router;

/**
 * {@code quarkus.http-signatures.verify.paths} protects plain Vert.x routes with no Quarkus Security involvement.
 */
public class VertxPathVerificationTest {

    static final String URL = "http://localhost:8081/inbox/alice";
    static final String BODY = "{\"type\":\"Follow\"}";

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class).addClasses(TestSigning.class, Routes.class)
                    .addAsResource("keys/ed25519.pem"))
            .overrideConfigKey("quarkus.http-signatures.keys.k1.location", "keys/ed25519.pem")
            .overrideConfigKey("quarkus.http-signatures.verify.paths", "/inbox/*");

    @ApplicationScoped
    public static class Routes {
        void register(@Observes Router router) {
            router.post("/inbox/:name").handler(ctx -> {
                VerificationResult r = ctx.get(VertxSignatureHandler.RESULT_KEY);
                ctx.response().end("ok " + (r == null ? "-" : r.keyId() + " " + r.scheme().id()));
            });
            router.post("/public").handler(ctx -> ctx.response().end("public"));
        }
    }

    static RequestSpecification signed(Scheme scheme, String body) {
        RequestSpecification spec = given();
        Map<String, String> headers = TestSigning.sign(scheme, "POST", URL, body);
        headers.forEach(spec::header);
        return spec.body(body);
    }

    @Test
    void unsignedIs401() {
        given().contentType("application/json").body(BODY).when().post("/inbox/alice").then().statusCode(401);
    }

    @Test
    void signedRfc9421Is200() {
        signed(Scheme.RFC9421, BODY).when().post("/inbox/alice").then().statusCode(200).body(equalTo("ok k1 rfc9421"));
    }

    @Test
    void signedCavageIs200() {
        signed(Scheme.CAVAGE, BODY).when().post("/inbox/alice").then().statusCode(200).body(equalTo("ok k1 cavage"));
    }

    @Test
    void tamperedBodyIs401() {
        RequestSpecification spec = given();
        TestSigning.sign(Scheme.RFC9421, "POST", URL, BODY).forEach(spec::header);
        spec.body("{\"type\":\"Delete\"}").when().post("/inbox/alice").then().statusCode(401);
    }

    @Test
    void garbageSignatureIs401NotError() {
        given().contentType("application/json").header("Signature", "sig1=(\"@method").header("Signature-Input", "%%%")
                .body(BODY).when().post("/inbox/alice").then().statusCode(401);
        given().contentType("application/json").header("Signature", "keyId=\"nobody\",signature=\"AAAA\"")
                .body(BODY).when().post("/inbox/alice").then().statusCode(401);
    }

    @Test
    void otherPathsUntouched() {
        given().contentType("application/json").body(BODY).when().post("/public").then().statusCode(200).body(equalTo("public"));
    }
}
