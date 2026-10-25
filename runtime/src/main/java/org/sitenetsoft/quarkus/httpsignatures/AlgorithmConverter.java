package org.sitenetsoft.quarkus.httpsignatures;

import org.eclipse.microprofile.config.spi.Converter;
import org.sitenetsoft.httpsignatures.Algorithm;

public class AlgorithmConverter implements Converter<Algorithm> {

    @Override
    public Algorithm convert(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return Algorithm.fromId(value.strip()).orElseThrow(
                () -> new IllegalArgumentException("Unknown HTTP signature algorithm: " + value));
    }
}
