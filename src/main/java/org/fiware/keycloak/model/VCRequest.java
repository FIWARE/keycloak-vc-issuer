package org.fiware.keycloak.model;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class VCRequest {

	private String templateId;
	private VCConfig config;
	private VCData credentialData;
}
