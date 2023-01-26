package org.fiware.keycloak;

import java.util.List;

public class VCAttribute {
	private final String name;
	private final List<String> value;

	public VCAttribute(String name, List<String> value) {
		this.name = name;
		this.value = value;
	}

	public String getName() {
		return name;
	}

	public List<String> getValue() {
		return value;
	}
}
