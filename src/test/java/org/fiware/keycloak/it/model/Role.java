package org.fiware.keycloak.it.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@EqualsAndHashCode
public class Role {

	public Set<String> names;
	public String target;
}
