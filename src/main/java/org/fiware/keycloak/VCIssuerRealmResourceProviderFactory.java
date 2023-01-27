package org.fiware.keycloak;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auto.service.AutoService;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

import java.net.URI;

/**
 * Factory implementation to provide the VCIssuer functionality as a realm resource.
 */
@AutoService(RealmResourceProviderFactory.class)
public class VCIssuerRealmResourceProviderFactory implements RealmResourceProviderFactory {

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
	private static final Logger LOGGER = Logger.getLogger(VCIssuerRealmResourceProviderFactory.class);
	private static final String ID = "verifiable-credential";

	private String issuerDid;
	private URI waltidURL;

	@Override
	public RealmResourceProvider create(KeycloakSession keycloakSession) {
		LOGGER.debug("Create vc-issuer resource provider");
		return new VCIssuerRealmResourceProvider(
				keycloakSession,
				issuerDid,
				new WaltIdClient(waltidURL, OBJECT_MAPPER),
				new AppAuthManager.BearerTokenAuthenticator(
						keycloakSession));
	}

	@Override
	public void init(Config.Scope config) {
		// read the issuer did and the address of walt from the realm resource.
		issuerDid = System.getenv("VCISSUER_ISSUER_DID");
		waltidURL = URI.create(System.getenv("VCISSUER_WALTID_ADDRESS"));
		LOGGER.infof("VCIssuerRealmResourceProviderFactory configured with issuerDID %s and walt-id %s.", issuerDid,
				waltidURL);
	}

	@Override
	public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
		// nothing to do here.
	}

	@Override
	public void close() {
		// specific resources to be closed
	}

	@Override
	public String getId() {
		return ID;
	}
}
