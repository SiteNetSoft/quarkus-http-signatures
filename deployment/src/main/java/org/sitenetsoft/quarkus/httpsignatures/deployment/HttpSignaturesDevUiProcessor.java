package org.sitenetsoft.quarkus.httpsignatures.deployment;

import org.sitenetsoft.quarkus.httpsignatures.devui.HttpSignaturesJsonRpcService;

import io.quarkus.deployment.IsDevelopment;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.devui.spi.JsonRPCProvidersBuildItem;
import io.quarkus.devui.spi.page.CardPageBuildItem;
import io.quarkus.devui.spi.page.Page;

public class HttpSignaturesDevUiProcessor {

    @BuildStep(onlyIf = IsDevelopment.class)
    CardPageBuildItem card() {
        CardPageBuildItem card = new CardPageBuildItem();
        card.addPage(Page.webComponentPageBuilder()
                .title("Verify")
                .icon("font-awesome-solid:signature")
                .componentLink("qwc-http-signatures-verify.js"));
        card.addPage(Page.externalPageBuilder("RFC 9421")
                .url("https://www.rfc-editor.org/rfc/rfc9421")
                .icon("font-awesome-solid:book")
                .doNotEmbed());
        return card;
    }

    @BuildStep(onlyIf = IsDevelopment.class)
    JsonRPCProvidersBuildItem jsonRpc() {
        return new JsonRPCProvidersBuildItem(HttpSignaturesJsonRpcService.class);
    }
}
