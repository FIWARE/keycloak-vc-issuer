package org.fiware.keycloak.model.walt;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.Map;

// for waltId compatibility
@Data
@AllArgsConstructor
@NoArgsConstructor
@Setter
public class CredentialMetadata {

	private Map<String, FormatObject> formats;
	private List<CredentialDisplay> display;
}
