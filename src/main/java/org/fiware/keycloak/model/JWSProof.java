package org.fiware.keycloak.model;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class JWSProof {

    private String type;
    private String creator;
    private String created;
    private String verificationMethod;
    private String jws;
}
