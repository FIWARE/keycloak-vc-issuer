package org.fiware.keycloak.model;

import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Data
public class DIDKey {

	private String kty;
	private String d;
	private String use;
	private String crv;
	private String kid;
	private String x;
	private String alg;
}
