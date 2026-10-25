package org.sitenetsoft.quarkus.httpsignatures.deployment;

import org.sitenetsoft.httpsignatures.KeyResolver;
import org.sitenetsoft.quarkus.httpsignatures.CachingKeyResolver;
import org.sitenetsoft.quarkus.httpsignatures.ConfigKeyResolver;
import org.sitenetsoft.quarkus.httpsignatures.ConfigSigningKeyProvider;
import org.sitenetsoft.quarkus.httpsignatures.HttpSignaturesBuildTimeConfig;
import org.sitenetsoft.quarkus.httpsignatures.InMemoryNonceStore;
import org.sitenetsoft.quarkus.httpsignatures.NonceStore;
import org.sitenetsoft.quarkus.httpsignatures.ReactiveKeyResolver;
import org.sitenetsoft.quarkus.httpsignatures.ReactiveNonceStore;
import org.sitenetsoft.quarkus.httpsignatures.ReactiveSigningKeyProvider;
import org.sitenetsoft.quarkus.httpsignatures.SignatureContext;
import org.sitenetsoft.quarkus.httpsignatures.SigningKeyProvider;
import org.sitenetsoft.quarkus.httpsignatures.StaticKeys;
import org.sitenetsoft.quarkus.httpsignatures.VerificationPolicies;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.UnremovableBeanBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;

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
                        CachingKeyResolver.class, VerificationPolicies.class, SignatureContext.class)
                .setUnremovable()
                .build());
        unremovable.produce(UnremovableBeanBuildItem.beanTypes(KeyResolver.class, ReactiveKeyResolver.class,
                SigningKeyProvider.class, ReactiveSigningKeyProvider.class, NonceStore.class, ReactiveNonceStore.class));
    }
}
