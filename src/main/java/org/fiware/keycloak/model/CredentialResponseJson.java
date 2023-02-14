package org.fiware.keycloak.model;

import lombok.AllArgsConstructor;

/**
 * Credential response object as mandated by the {@see https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html}
 * and referenced in the European Digital Identity Wallet Architecture and Reference Framework
 * {@see https://digital-strategy.ec.europa.eu/en/library/european-digital-identity-wallet-architecture-and-reference-framework}
 */
@AllArgsConstructor
public class CredentialResponseJson {

	/**
	 * Format is a required field by th {@see https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html}
	 * OIDC4VC issuance spec, which is mandated by the European Digital Identity Wallet Architecture and Reference Framework
	 * {@see https://digital-strategy.ec.europa.eu/en/library/european-digital-identity-wallet-architecture-and-reference-framework}
	 */
	public static final CredentialFormat format = CredentialFormat.JWT_VC_JSON;

	/**
	 * The jwt encoded credential
	 */
	public String credential;
}
