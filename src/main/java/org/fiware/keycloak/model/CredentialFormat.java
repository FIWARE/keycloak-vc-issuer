package org.fiware.keycloak.model;

import lombok.Getter;

public enum CredentialFormat {

	JWT_VC_JSON("jwt_vc_json"),
	JWT_VC_JSON_LD("jwt_vc_json-ld"),
	LDP_VC("ldp_vc");

	@Getter
	private final String value;

	CredentialFormat(String value) {
		this.value = value;
	}
}
