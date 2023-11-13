package org.fiware.keycloak.it.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.*;
import org.fiware.keycloak.oidcvc.model.FormatVO;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@EqualsAndHashCode
@ToString
@JsonIgnoreProperties(ignoreUnknown = true)
public class CredentialObject {

	public String type;
	public FormatVO format;
}
