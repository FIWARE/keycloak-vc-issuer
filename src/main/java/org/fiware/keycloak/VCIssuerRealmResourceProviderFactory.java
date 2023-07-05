package org.fiware.keycloak;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auto.service.AutoService;
import org.fiware.keycloak.model.DIDKey;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

import java.io.File;
import java.io.IOException;
import java.time.Clock;
import java.util.Optional;

/**
 * Factory implementation to provide the VCIssuer functionality as a realm resource.
 */
@AutoService(RealmResourceProviderFactory.class)
public class VCIssuerRealmResourceProviderFactory implements RealmResourceProviderFactory {

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	private static final Logger LOGGER = Logger.getLogger(VCIssuerRealmResourceProviderFactory.class);
	public static final String ID = "verifiable-credential";

	private static final String WALTID_ADDRESS_ENV_VAR = "VCISSUER_WALTID_ADDRESS";
	private static final String WALTID_CORE_PORT_ENV_VAR = "VCISSUER_WALTID_CORE_PORT";
	private static final String WALTID_SIGNATORY_PORT_ENV_VAR = "VCISSUER_WALTID_SIGNATORY_PORT";
	private static final String ISSUER_DID_ENV_VAR = "VCISSUER_ISSUER_DID";
	private static final String ISSUER_DID_KEY_FILE_ENV_VAR = "VCISSUER_ISSUER_KEY_FILE";

	private String issuerDid;
	private String waltIdURL;
	private int corePort = 7000;
	private int signatoryPort = 7001;

	private WaltIdClient waltIdClient;

	@Override
	public RealmResourceProvider create(KeycloakSession keycloakSession) {
		LOGGER.debug("Create vc-issuer resource provider");

		return new VCIssuerRealmResourceProvider(
				keycloakSession,
				issuerDid,
				waltIdClient,
				new AppAuthManager.BearerTokenAuthenticator(
						keycloakSession),
				OBJECT_MAPPER,
				Clock.systemUTC());
	}

	@Override
	public void init(Config.Scope config) {
		try {
			// read the address of walt from the realm resource.
			waltIdURL = System.getenv(WALTID_ADDRESS_ENV_VAR);
			initializeCorePort();
			initializeSignatoryPort();

		} catch (RuntimeException e) {
			LOGGER.warn("Was not able to initialize the VCIssuerRealmResourceProvider. Issuing VCs is not supported.",
					e);
		}
		waltIdClient = new WaltIdClient(waltIdURL, corePort, signatoryPort, OBJECT_MAPPER);

		try {
			LOGGER.info("Starting to initialization of issuer and key.");
			// import the issuer key, if present.
			Optional<String> keyId = importIssuerKey();
			keyId.ifPresentOrElse(k -> LOGGER.infof("Imported key %s.", keyId),
					() -> LOGGER.warnf("No key was imported."));
			initializeIssuerDid(keyId);
			LOGGER.infof("VCIssuerRealmResourceProviderFactory configured with issuerDID %s and walt-id %s.", issuerDid,
					waltIdURL);
		} catch (WaltIdConnectException waltIdConnectException) {
			LOGGER.error("Was not able to initialize the issuer did. Issuing VCs is not available.",
					waltIdConnectException);
		}

	}

	private void initializeCorePort() {
		try {
			corePort = Integer.parseInt(System.getenv(WALTID_CORE_PORT_ENV_VAR));
		} catch (RuntimeException e) {
			LOGGER.infof("No specific core port configured. Will use the default %d.", corePort);
		}
	}

	private void initializeSignatoryPort() {
		try {
			signatoryPort = Integer.parseInt(System.getenv(WALTID_SIGNATORY_PORT_ENV_VAR));
		} catch (RuntimeException e) {
			LOGGER.infof("No specific signatory port configured. Will use the default %d.", signatoryPort);
		}
	}

	private void initializeIssuerDid(Optional<String> keyId) {
		try {
			issuerDid = Optional.ofNullable(System.getenv(ISSUER_DID_ENV_VAR))
					.orElseGet(() -> waltIdClient.createDid());
			if (!existsDid(issuerDid)) {

				LOGGER.infof("The configured did does not yet exist, we try to import %s with the key %s.", issuerDid,
						keyId.orElse(""));
				// issuer does not exist, try to import
				keyId.ifPresent(key -> waltIdClient.importDid(issuerDid, key));
			} else {
				LOGGER.infof("Did %s already exists. Nothing else to import.", issuerDid);
			}
		}
		// catch NPE(in case no such env is set and null in case an null string is set.)
		catch (NullPointerException npe) {
			LOGGER.info("No issuer did provided, will create one.");
			issuerDid = waltIdClient.createDid();
		}
	}

	private Optional<String> importIssuerKey() {

		Optional<String> keyFileEnv = Optional.ofNullable(System.getenv(ISSUER_DID_KEY_FILE_ENV_VAR));
		if (keyFileEnv.isEmpty()) {
			LOGGER.info("No keyfile is provided, skip key import.");
			return Optional.empty();
		}

		File keyFile = new File(keyFileEnv.get());
		if (!keyFile.exists()) {
			LOGGER.warnf("Despite being configured, no keyfile exists at %s. Skip import.", keyFileEnv.get());
			return Optional.empty();
		}

		try {
			DIDKey keyToImport = OBJECT_MAPPER.readValue(keyFile, DIDKey.class);
			return Optional.ofNullable(waltIdClient.importDIDKey(keyToImport));
		} catch (IOException e) {
			LOGGER.warnf("The keyfile %s is not a valid key. Skip import.", keyFileEnv.get(), e);
			return Optional.empty();
		} catch (WaltIdConnectException e) {
			LOGGER.warnf("Was not able to import the key. Skip import.", e);
			return Optional.empty();
		}
	}

	private boolean existsDid(String issuerDid) {
		return waltIdClient.getDids().contains(issuerDid);
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
