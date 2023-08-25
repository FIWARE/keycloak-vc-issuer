package org.fiware.keycloak.model.walt;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class CredentialOfferURI {
    private String issuer;
    private String nonce;
}
