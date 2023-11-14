package org.fiware.keycloak.signing;

import java.util.List;

public enum AlgorithmType {

	EdDSA_Ed25519(List.of("eddsa", "ed25519", "eddsa_ed25519")),
	ECDSA_Secp256k1(List.of("ecdsa", "secp256k1", "ecdsa_secp256k1")),
	RSA(List.of("rsa", "ps256", "rs256"));

	private final List<String> values;

	AlgorithmType(List<String> values) {
		this.values = values;
	}

	public List<String> getValues() {
		return values;
	}

	public static AlgorithmType getByValue(String value) {
		for (AlgorithmType algorithmType : values())
			if (algorithmType.values.stream().anyMatch(value::equalsIgnoreCase)) {
				return algorithmType;
			}
		throw new IllegalArgumentException(String.format("No algorithm of type %s exists.", value));
	}
}
