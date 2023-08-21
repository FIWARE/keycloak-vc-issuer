package org.fiware.keycloak.it.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import java.util.List;
import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@ToString
@EqualsAndHashCode
public class VerifiableCredential {
	public Set<String> type;
	@JsonProperty("@context")
	public List<String> context;
	public String id;
	public String issuer;
	public String issuanceDate;
	public String issued;
	public String validFrom;
	public String expirationDate;
	public CredentialSchema credentialSchema;
	public CredentialSubject credentialSubject;
	public JWSProof proof;
}
