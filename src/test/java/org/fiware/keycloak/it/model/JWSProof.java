package org.fiware.keycloak.it.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@EqualsAndHashCode
public class JWSProof {

	public String type;
	public String creator;
	public String created;
	public String verificationMethod;
	public String jws;
}
