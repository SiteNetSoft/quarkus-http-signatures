package org.sitenetsoft.quarkus.httpsignatures;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

@ConfigMapping(prefix = "quarkus.http-signatures")
@ConfigRoot(phase = ConfigPhase.BUILD_TIME)
public interface HttpSignaturesBuildTimeConfig {

    /**
     * Set to false to remove HTTP signature verification and signing from the build.
     */
    @WithDefault("true")
    boolean enabled();
}
