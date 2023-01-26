package org.fiware.keycloak.model;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Builder
@Data
public class VCClaims {
	private String firstName;
	private String familyName;
	private String email;
	private List<Role> roles;

	private Map<String, String> additionalClaims;

	@JsonAnyGetter
	public Map<String, String> getAdditionalClaims() {
		return additionalClaims;
	}
}
