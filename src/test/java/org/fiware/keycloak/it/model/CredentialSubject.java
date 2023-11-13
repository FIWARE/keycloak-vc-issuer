package org.fiware.keycloak.it.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.*;

import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@Setter
@EqualsAndHashCode
@ToString
@JsonIgnoreProperties(ignoreUnknown = true)
public class CredentialSubject {

	public String id;
	public String familyName;
	public String firstName;
	public String email;
	public Set<Role> roles;

}
