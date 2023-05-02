package org.fiware.keycloak.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VCRequest {

	private String templateId;
	private VCConfig config;
	private VCData credentialData;
}
