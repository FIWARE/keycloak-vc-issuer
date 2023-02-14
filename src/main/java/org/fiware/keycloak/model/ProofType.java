package org.fiware.keycloak.model;

import lombok.Getter;

public enum ProofType {
	JWT("jwt");

	@Getter
	private final String value;

	ProofType(String value) {
		this.value = value;
	}
}
