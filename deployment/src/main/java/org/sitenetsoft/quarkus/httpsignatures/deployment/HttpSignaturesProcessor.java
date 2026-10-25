package org.sitenetsoft.quarkus.httpsignatures.deployment;

import org.sitenetsoft.httpsignatures.KeyResolver;
import org.sitenetsoft.quarkus.httpsignatures.CachingKeyResolver;
import org.sitenetsoft.quarkus.httpsignatures.ConfigKeyResolver;
import org.sitenetsoft.quarkus.httpsignatures.ConfigSigningKeyProvider;
import org.sitenetsoft.quarkus.httpsignatures.HttpSignaturesBuildTimeConfig;
import org.sitenetsoft.quarkus.httpsignatures.HttpSignaturesRecorder;
import org.sitenetsoft.quarkus.httpsignatures.InMemoryNonceStore;
import org.sitenetsoft.quarkus.httpsignatures.NonceStore;
import org.sitenetsoft.quarkus.httpsignatures.ReactiveKeyResolver;
import org.sitenetsoft.quarkus.httpsignatures.ReactiveNonceStore;
import org.sitenetsoft.quarkus.httpsignatures.ReactiveSigningKeyProvider;
import org.sitenetsoft.quarkus.httpsignatures.SignatureContext;
import org.sitenetsoft.quarkus.httpsignatures.SigningKeyProvider;
import org.sitenetsoft.quarkus.httpsignatures.StaticKeys;
import org.sitenetsoft.quarkus.httpsignatures.VerificationPolicies;
import org.sitenetsoft.quarkus.httpsignatures.client.RequestSigner;
import org.sitenetsoft.quarkus.httpsignatures.client.SchemeMemory;
import org.sitenetsoft.quarkus.httpsignatures.client.SigningHttpClient;
import org.sitenetsoft.quarkus.httpsignatures.client.VertxRequestSigner;
import org.sitenetsoft.quarkus.httpsignatures.rest.SignatureRequired;
import org.sitenetsoft.quarkus.httpsignatures.rest.SignatureRequiredFilter;
import org.sitenetsoft.quarkus.httpsignatures.security.HttpSignatureAuthenticationMechanism;
import org.sitenetsoft.quarkus.httpsignatures.security.HttpSignatureIdentityProvider;
import org.sitenetsoft.quarkus.httpsignatures.vertx.RequestVerifier;
import org.sitenetsoft.quarkus.httpsignatures.vertx.VertxSignatureHandler;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.UnremovableBeanBuildItem;
import io.quarkus.deployment.Capabilities;
import io.quarkus.deployment.Capability;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.AdditionalIndexedClassesBuildItem;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.vertx.http.deployment.RouteBuildItem;

class HttpSignaturesProcessor {

    static final String FEATURE = "http-signatures";

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }

    @BuildStep
    void beans(HttpSignaturesBuildTimeConfig config, BuildProducer<AdditionalBeanBuildItem> beans,
            BuildProducer<UnremovableBeanBuildItem> unremovable) {
        if (!config.enabled()) {
            return;
        }
        beans.produce(AdditionalBeanBuildItem.builder()
                .addBeanClasses(StaticKeys.class, ConfigKeyResolver.class, ConfigSigningKeyProvider.class, InMemoryNonceStore.class,
                        CachingKeyResolver.class, VerificationPolicies.class, SignatureContext.class, RequestVerifier.class,
                        VertxSignatureHandler.class, SchemeMemory.class, RequestSigner.class, SigningHttpClient.class,
                        VertxRequestSigner.class)
                .setUnremovable()
                .build());
        unremovable.produce(UnremovableBeanBuildItem.beanTypes(KeyResolver.class, ReactiveKeyResolver.class,
                SigningKeyProvider.class, ReactiveSigningKeyProvider.class, NonceStore.class, ReactiveNonceStore.class));
    }

    @BuildStep
    void security(HttpSignaturesBuildTimeConfig config, Capabilities capabilities, BuildProducer<AdditionalBeanBuildItem> beans) {
        if (config.enabled() && capabilities.isPresent(Capability.SECURITY)) {
            beans.produce(AdditionalBeanBuildItem.builder()
                    .addBeanClasses(HttpSignatureAuthenticationMechanism.class, HttpSignatureIdentityProvider.class)
                    .setUnremovable()
                    .build());
        }
    }

    @BuildStep
    void restFilter(HttpSignaturesBuildTimeConfig config, Capabilities capabilities, BuildProducer<AdditionalBeanBuildItem> beans,
            BuildProducer<AdditionalIndexedClassesBuildItem> indexed) {
        if (config.enabled() && capabilities.isPresent(Capability.REST)) {
            beans.produce(AdditionalBeanBuildItem.unremovableOf(SignatureRequiredFilter.class));
            indexed.produce(new AdditionalIndexedClassesBuildItem(SignatureRequiredFilter.class.getName(), SignatureRequired.class.getName()));
        }
    }

    @BuildStep
    @Record(ExecutionTime.STATIC_INIT)
    void pathVerification(HttpSignaturesBuildTimeConfig config, HttpSignaturesRecorder recorder, BuildProducer<RouteBuildItem> routes) {
        if (!config.enabled()) {
            return;
        }
        // one early global route; the handler checks quarkus.http-signatures.verify.paths at runtime and calls next()
        routes.produce(RouteBuildItem.builder()
                .orderedRoute("/*", -1_000_000)
                .handler(recorder.pathHandler())
                .build());
    }
}
