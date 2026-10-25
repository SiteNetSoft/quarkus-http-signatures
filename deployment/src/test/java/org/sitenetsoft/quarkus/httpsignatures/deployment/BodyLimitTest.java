package org.sitenetsoft.quarkus.httpsignatures.deployment;

import static io.restassured.RestAssured.given;

import java.util.Map;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.sitenetsoft.httpsignatures.Scheme;

import io.quarkus.test.QuarkusUnitTest;
import io.restassured.specification.RequestSpecification;
import io.vertx.ext.web.Router;

/**
 * A request carrying a Signature header must not make the verifier buffer an unbounded body.
 */
public class BodyLimitTest {

    static final String URL = "http://localhost:8081/inbox/alice";

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class).addClasses(TestSigning.class, Routes.class)
                    .addAsResource("keys/ed25519.pem"))
            .overrideConfigKey("quarkus.http-signatures.keys.k1.location", "keys/ed25519.pem")
            .overrideConfigKey("quarkus.http-signatures.verify.paths", "/inbox/*")
            .overrideConfigKey("quarkus.http-signatures.verify.max-body-size", "1K");

    @ApplicationScoped
    public static class Routes {
        void register(@Observes Router router) {
            router.post("/inbox/:name").handler(ctx -> ctx.response().end("ok"));
        }
    }

    static RequestSpecification signed(String body) {
        RequestSpecification spec = given();
        Map<String, String> headers = TestSigning.sign(Scheme.RFC9421, "POST", URL, body);
        headers.forEach(spec::header);
        return spec.body(body);
    }

    @Test
    void smallSignedBodyIsAccepted() {
        signed("{\"a\":1}").when().post("/inbox/alice").then().statusCode(200);
    }

    @Test
    void oversizedBodyIsRejectedWithoutBeingVerified() {
        signed("x".repeat(4096)).when().post("/inbox/alice").then().statusCode(413);
    }
}
