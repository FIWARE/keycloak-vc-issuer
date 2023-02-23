package org.fiware.keycloak.it.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import org.fiware.keycloak.oidcvc.model.FormatVO;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@EqualsAndHashCode
public class CredentialObject {

	public String type;
	public FormatVO format;
}
