package org.sitenetsoft.quarkus.httpsignatures.deployment;

import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;

class HttpSignaturesProcessor {

    static final String FEATURE = "http-signatures";

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }
}
