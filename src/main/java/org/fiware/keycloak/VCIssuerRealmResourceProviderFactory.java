package org.fiware.keycloak;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auto.service.AutoService;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

@AutoService(RealmResourceProviderFactory.class)
public class VCIssuerRealmResourceProviderFactory implements RealmResourceProviderFactory {

	private final static ObjectMapper OBJECT_MAPPER = new ObjectMapper();
	private final static Logger LOGGER = Logger.getLogger(VCIssuerRealmResourceProviderFactory.class);
	private static final String ID = "verifiable-credential";

	@Override
	public RealmResourceProvider create(KeycloakSession keycloakSession) {
		LOGGER.warn("Create resource provider");
		String issuerDid = System.getenv("VCISSUER_ISSUER_DID");
		String waltidURL = System.getenv("VCISSUER_WALTID_ADDRESS");
		return new VCIssuerRealmResourceProvider(keycloakSession, issuerDid, waltidURL, OBJECT_MAPPER);
	}

	@Override
	public void init(Config.Scope config) {
	}

	@Override
	public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

	}

	@Override
	public void close() {
		LOGGER.warn("Close resource provider");

	}

	@Override
	public String getId() {
		return ID;
	}
}
