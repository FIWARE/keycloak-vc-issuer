package org.fiware.keycloak.it.model;

import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@EqualsAndHashCode
@ToString
public class JWSProof {

	public String type;
	public String creator;
	public String created;
	public String verificationMethod;
	public String jws;
}
