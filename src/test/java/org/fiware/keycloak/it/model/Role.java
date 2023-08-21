package org.fiware.keycloak.it.model;

import lombok.*;

import java.util.List;
import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@EqualsAndHashCode
@ToString
public class Role {

	public Set<String> names;
	public String target;
}
