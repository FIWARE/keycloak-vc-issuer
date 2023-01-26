package org.fiware.keycloak;

import lombok.Data;

import java.util.Map;

@Data
public class VCClient {

	private String clientDid;
	private String supportedVCTypes;
	private String description;
	private String name;
	// not primitive to stay nullable.
	private Long expiryInMin;
	private Map<String, String> additionalClaims;
}
