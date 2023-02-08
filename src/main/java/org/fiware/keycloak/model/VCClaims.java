package org.fiware.keycloak.model;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import lombok.Builder;
import lombok.Data;

import java.util.Map;
import java.util.Set;

@Builder
@Data
public class VCClaims {
	private String firstName;
	private String familyName;
	private String email;
	private Set<Role> roles;

	private Map<String, String> additionalClaims;

	@JsonAnyGetter
	public Map<String, String> getAdditionalClaims() {
		return additionalClaims;
	}
}
