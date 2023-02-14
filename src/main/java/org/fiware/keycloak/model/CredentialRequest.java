package org.fiware.keycloak.model;

import lombok.Data;

import java.util.List;

/**
 * Credential request as mandated by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
 */
@Data
public class CredentialRequest {

	private CredentialFormat format;
	private List<String> types;
	private RequestProof proof;
}
