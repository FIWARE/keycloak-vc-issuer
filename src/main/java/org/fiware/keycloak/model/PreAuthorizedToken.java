package org.fiware.keycloak.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import org.keycloak.representations.JsonWebToken;

public class PreAuthorizedToken extends JsonWebToken {

	@Getter
	@JsonProperty("pre-authorized")
	private boolean preAuthorized = true;
}
