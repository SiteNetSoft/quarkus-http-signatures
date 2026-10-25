package org.sitenetsoft.quarkus.httpsignatures.deployment;

import static io.restassured.RestAssured.given;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;
import io.vertx.ext.web.Router;

/**
 * {@code verify.paths} must protect routes at the server root even when the app lives under
 * {@code quarkus.http.root-path}.
 */
public class RootPathVerificationTest {

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class).addClasses(Routes.class).addAsResource("keys/ed25519.pem"))
            .overrideConfigKey("quarkus.http.root-path", "/api")
            .overrideConfigKey("quarkus.http-signatures.keys.k1.location", "keys/ed25519.pem")
            .overrideConfigKey("quarkus.http-signatures.verify.paths", "/inbox/*");

    @ApplicationScoped
    public static class Routes {
        void register(@Observes Router router) {
            router.post("/inbox/:name").handler(ctx -> ctx.response().end("ok"));
        }
    }

    @Test
    void unsignedRootLevelInboxIs401() {
        given().baseUri("http://localhost:8081").basePath("/").contentType("application/json").body("{}")
                .when().post("/inbox/alice").then().statusCode(401);
    }
}
