package org.fiware.keycloak.model.walt;

import lombok.Getter;

public enum ProofType {

	LD_PROOF("LD_PROOF"),
	JWT("JWT");

	@Getter
	private final String value;

	ProofType(String value) {
		this.value = value;
	}
}
