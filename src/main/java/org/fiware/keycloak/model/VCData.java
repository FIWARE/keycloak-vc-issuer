package org.fiware.keycloak.model;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class VCData {
	private VCClaims credentialSubject;
}
