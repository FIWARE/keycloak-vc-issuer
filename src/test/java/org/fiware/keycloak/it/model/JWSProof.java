package org.fiware.keycloak.it.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@EqualsAndHashCode
@ToString
@JsonIgnoreProperties(ignoreUnknown = true)
public class JWSProof {

	public String type;
	public String creator;
	public String created;
	public String verificationMethod;
	public String jws;
}
