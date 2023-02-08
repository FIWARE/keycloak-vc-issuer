package org.fiware.keycloak.it.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@EqualsAndHashCode
public class CredentialSubject {

	public String id;
	public String familyName;
	public String firstName;
	public String email;
	public Set<Role> roles;

}
