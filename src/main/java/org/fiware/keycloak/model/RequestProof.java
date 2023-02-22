package org.fiware.keycloak.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class RequestProof {

	@JsonProperty("proof_type")
	private ProofType proofType;
	private String jwt;
}
