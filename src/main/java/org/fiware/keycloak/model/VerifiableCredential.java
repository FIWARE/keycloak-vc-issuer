package org.fiware.keycloak.model;

import com.fasterxml.jackson.annotation.JsonProperty;
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
public class VerifiableCredential {

	public String format = "jwt_vc_json";
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
