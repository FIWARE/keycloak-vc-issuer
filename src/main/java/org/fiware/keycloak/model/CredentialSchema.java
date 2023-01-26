package org.fiware.keycloak.model;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class CredentialSchema {

    private String id;
    private String type;

}
