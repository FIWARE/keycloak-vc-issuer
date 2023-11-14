package org.fiware.keycloak;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.http.media.MediaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auto.service.AutoService;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Factory implementation to provide the VCIssuer functionality as a realm resource.
 */
@AutoService(RealmResourceProviderFactory.class)
public class VCIssuerRealmResourceProviderFactory implements RealmResourceProviderFactory {

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	private static final Logger LOGGER = Logger.getLogger(VCIssuerRealmResourceProviderFactory.class);
	public static final String ID = "verifiable-credential";

	private final Clock clock = Clock.systemUTC();

	@Override
	public RealmResourceProvider create(KeycloakSession keycloakSession) {
		LOGGER.debug("Create vc-issuer resource provider");

		String issuerDid = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("issuerDid"))
				.orElseThrow(() -> new VCIssuerException("No issuerDid  configured."));
		String keyPath = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("keyPath"))
				.orElseThrow(() -> new VCIssuerException("No keyPath configured."));
		return new VCIssuerRealmResourceProvider(
				keycloakSession,
				issuerDid, keyPath,
				new AppAuthManager.BearerTokenAuthenticator(
						keycloakSession), OBJECT_MAPPER, clock
		);
	}

	@Override
	public void init(Config.Scope config) {
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
