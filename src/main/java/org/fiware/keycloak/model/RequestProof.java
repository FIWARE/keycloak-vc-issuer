package org.fiware.keycloak.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import org.fiware.keycloak.oidcvc.model.ProofTypeVO;

@Data
public class RequestProof {

	@JsonProperty("proof_type")
	private ProofTypeVO proofType;
	private String jwt;
}
