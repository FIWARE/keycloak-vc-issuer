package org.fiware.keycloak.it.model;

import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@EqualsAndHashCode
@ToString
public class CredentialSchema {

    public String id;
    public String type;

}
