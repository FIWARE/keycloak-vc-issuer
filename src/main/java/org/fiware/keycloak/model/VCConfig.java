package org.fiware.keycloak.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Builder
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VCConfig {

	private String issuerDid;
	private String subjectDid;
	private String proofType;
	private String expirationDate;

}


