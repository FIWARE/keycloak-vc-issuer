package org.fiware.keycloak.model;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Builder
@Data
public class Role {

	private List<String> names;
	private String target;

}
