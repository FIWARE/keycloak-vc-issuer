package org.fiware.keycloak.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Builder
@Data
public class VerifiableCredential {

    private List<String> type;
    @JsonProperty("@context")
    private List<String> context;
    private String id;
    private String issuer;
    private String issuanceDate;
    private String issued;
    private String validFrom;
    private CredentialSchema credentialSchema;
    private CredentialSubject credentialSubject;
    private JWSProof proof;
}
