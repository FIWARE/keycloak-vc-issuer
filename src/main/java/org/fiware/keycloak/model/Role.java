package org.fiware.keycloak.model;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@AllArgsConstructor
@Data
public class Role {

	private List<String> names;
	private String target;

}
