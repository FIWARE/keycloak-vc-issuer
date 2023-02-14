package org.fiware.keycloak.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.keycloak.Token;
import org.keycloak.TokenCategory;

@Data
@AllArgsConstructor
public class CredentialToken implements Token {

	private VerifiableCredential credential;
	private String iss;
	private long nbf;
	private String jti;
	private String sub;

	@Override public TokenCategory getCategory() {
		return TokenCategory.USERINFO;
	}
}
