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

	private static final String ISSUER_DID_ENV_VAR = "VCISSUER_ISSUER_DID";
	private static final String ISSUER_DID_KEY_FILE_ENV_VAR = "VCISSUER_ISSUER_KEY_FILE";

	private final Clock clock = Clock.systemUTC();
	private String issuerDid;

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
		var paths = List.of("security-v1.jsonld", "security-v2.jsonld", "security-v3-unstable.jsonld",
				"security-bbs-v1.jsonld",
				"suites-secp256k1-2019.jsonld", "suites-ed25519-2018.jsonld", "suites-ed25519-2020.jsonld",
				"suites-x25519-2019.jsonld", "suites-jws-2020.jsonld");
		for (String path : paths) {
			try {
				JsonDocument.of(MediaType.JSON_LD,
						Objects.requireNonNull(LDSecurityContexts.class.getResourceAsStream(path)));
			} catch (JsonLdError e) {
				LOGGER.warnf("Failed to load %s", path);
				LOGGER.error("Failed", e);
				//throw new RuntimeException(e);
			}
		}

		LOGGER.warnf("Stream %s", LDSecurityContexts.class.getResource("suites-jws-2020.jsonld"));
		LOGGER.warnf("Stream %s", LDSecurityContexts.class.getResourceAsStream("suites-jws-2020.jsonld"));

		config.getPropertyNames().stream()
				.forEach(pn -> LOGGER.warnf("%s : %s ", pn, config.get(pn)));
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
