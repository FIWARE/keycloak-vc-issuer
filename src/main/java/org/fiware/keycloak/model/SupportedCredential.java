package org.fiware.keycloak.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.fiware.keycloak.oidcvc.model.FormatVO;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SupportedCredential {

	public String type;
	public FormatVO format;
}
