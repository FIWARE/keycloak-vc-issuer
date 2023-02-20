package org.fiware.keycloak;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.fiware.keycloak.model.SupportedCredential;

import java.util.List;
import java.util.Map;

/**
 * Pojo, containing all information required to create a VCClient.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class SIOP2Client {

	/**
	 * Did of the target/client, will be used as client-id
	 */
	private String clientDid;
	/**
	 * Comma-separated list of supported credentials types
	 */
	private List<SupportedCredential> supportedVCTypes;
	/**
	 * Description of the client, will f.e. be displayed in the admin-console
	 */
	private String description;
	/**
	 * Human-readable name of the client
	 */
	private String name;
	/**
	 * Expiry for the credentials to be created.
	 * Be aware: this used the non-primitive long to stay nullable.
	 */
	private Long expiryInMin;
	/**
	 * A map of additional claims that will be provided within the generated VC.
	 */
	private Map<String, String> additionalClaims;
}
