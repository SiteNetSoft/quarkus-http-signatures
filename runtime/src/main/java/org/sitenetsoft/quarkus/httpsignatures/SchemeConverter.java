package org.sitenetsoft.quarkus.httpsignatures;

import org.eclipse.microprofile.config.spi.Converter;
import org.sitenetsoft.httpsignatures.Scheme;

public class SchemeConverter implements Converter<Scheme> {

    @Override
    public Scheme convert(String value) {
        return value == null || value.isBlank() ? null : Scheme.fromId(value.strip());
    }
}
