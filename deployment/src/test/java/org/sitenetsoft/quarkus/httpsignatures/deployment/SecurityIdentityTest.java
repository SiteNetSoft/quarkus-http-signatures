package org.sitenetsoft.quarkus.httpsignatures.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.sitenetsoft.httpsignatures.Scheme;
import org.sitenetsoft.quarkus.httpsignatures.SignatureContext;

import io.quarkus.security.Authenticated;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.specification.RequestSpecification;

/**
 * A verified signature becomes a {@link SecurityIdentity} whose principal is the key id.
 */
public class SecurityIdentityTest {

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class).addClasses(TestSigning.class, WhoAmI.class)
                    .addAsResource("keys/ed25519.pem"))
            .overrideConfigKey("quarkus.http-signatures.keys.k1.location", "keys/ed25519.pem");

    @Path("/whoami")
    public static class WhoAmI {
        @Inject
        SecurityIdentity identity;

        @Inject
        SignatureContext signature;

        @GET
        @Authenticated
        public String get() {
            return identity.getPrincipal().getName() + " " + signature.result().orElseThrow().scheme().id();
        }

        @POST
        @Authenticated
        public String post(String body) {
            return identity.getPrincipal().getName() + " " + body.length();
        }

        @GET
        @Path("/open")
        public String open() {
            return identity.isAnonymous() ? "anonymous" : identity.getPrincipal().getName();
        }
    }

    static RequestSpecification signed(Scheme scheme, String method, String path, String body) {
        RequestSpecification spec = given();
        TestSigning.sign(scheme, method, "http://localhost:8081" + path, body).forEach(spec::header);
        return body == null ? spec : spec.body(body);
    }

    @Test
    void signedGetIsAuthenticatedAsKeyId() {
        signed(Scheme.RFC9421, "GET", "/whoami", null).when().get("/whoami").then().statusCode(200).body(equalTo("k1 rfc9421"));
    }

    @Test
    void signedPostBodyReachesTheEndpoint() {
        signed(Scheme.CAVAGE, "POST", "/whoami", "{\"a\":1}").when().post("/whoami").then().statusCode(200).body(equalTo("k1 7"));
    }

    @Test
    void unsignedIs401() {
        given().when().get("/whoami").then().statusCode(401).header("WWW-Authenticate", equalTo("Signature"));
    }

    @Test
    void openEndpointStaysAnonymousWithoutSignature() {
        given().when().get("/whoami/open").then().statusCode(200).body(equalTo("anonymous"));
    }

    @Test
    void badSignatureOnOpenEndpointIs401() {
        given().header("Signature", "keyId=\"k1\",signature=\"AAAA\"").when().get("/whoami/open").then().statusCode(401);
    }
}
