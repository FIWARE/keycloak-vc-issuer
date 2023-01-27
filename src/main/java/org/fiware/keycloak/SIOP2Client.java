package org.fiware.keycloak;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

/**
 * Pojo, containing all information required to create a VCClient.
 */
@Data
@Builder
public class SIOP2Client {

	/**
	 * Did of the target/client, will be used as client-id
	 */
	private String clientDid;
	/**
	 * Comma-separated list of supported credentials types
	 */
	private String supportedVCTypes;
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
