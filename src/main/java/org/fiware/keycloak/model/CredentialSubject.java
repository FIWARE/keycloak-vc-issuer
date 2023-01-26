package org.fiware.keycloak.model;

import lombok.Builder;
import lombok.Data;

import java.util.List;
@Builder
@Data
public class CredentialSubject {

    private String id;
    private String familyName;
    private String firstName;
    private String email;
    private List<Role> roles;

}
