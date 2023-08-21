package org.fiware.keycloak.it.model;

import lombok.*;

import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@EqualsAndHashCode
@ToString
public class CredentialSubject {

	public String id;
	public String familyName;
	public String firstName;
	public String email;
	public Set<Role> roles;

}
