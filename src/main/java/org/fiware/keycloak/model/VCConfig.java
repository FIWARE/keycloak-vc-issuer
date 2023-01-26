package org.fiware.keycloak.model;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class VCConfig {

	private String issuerDid;
	private String subjectDid;
	private String proofType;
	private String expirationDate;

}
