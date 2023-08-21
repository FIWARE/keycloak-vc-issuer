package org.fiware.keycloak.it.model;

import lombok.*;
import org.fiware.keycloak.oidcvc.model.FormatVO;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@EqualsAndHashCode
@ToString
public class CredentialObject {

	public String type;
	public FormatVO format;
}
