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

/**
 * Factory implementation to provide the VCIssuer functionality as a realm resource.
 */
@AutoService(RealmResourceProviderFactory.class)
public class VCIssuerRealmResourceProviderFactory implements RealmResourceProviderFactory {

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
	private static final Logger LOGGER = Logger.getLogger(VCIssuerRealmResourceProviderFactory.class);
	private static final String ID = "verifiable-credential";

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
						keycloakSession));
	}

	@Override
	public void init(Config.Scope config) {
		try {

			// read the address of walt from the realm resource.
			waltIdURL = System.getenv("VCISSUER_WALTID_ADDRESS");
			initializeCorePort();
			initializeSignatoryPort();
			LOGGER.infof("VCIssuerRealmResourceProviderFactory configured with issuerDID {} and walt-id {}.", issuerDid,
					waltIdURL);
		} catch (RuntimeException e) {
			LOGGER.warn("Was not able to initialize the VCIssuerRealmResourceProvider. Issuing VCs is not supported.",
					e);
		}
		waltIdClient = new WaltIdClient(waltIdURL, corePort, signatoryPort, OBJECT_MAPPER);

		try {
			initializeIssuerDid();
		} catch (WaltIdConnectException waltIdConnectException) {
			LOGGER.warnf("Was not able to initialize the issuer did. Issuing VCs is not available.",
					waltIdConnectException);
		}

	}

	private void initializeCorePort() {
		try {
			corePort = Integer.parseInt(System.getenv("VCISSUER_WALTID_CORE_PORT"));
		} catch (RuntimeException e) {
			LOGGER.infof("No specific core port configured. Will use the default {}.", corePort);
		}
	}

	private void initializeSignatoryPort() {
		try {
			signatoryPort = Integer.parseInt(System.getenv("VCISSUER_WALTID_SIGNATORY_PORT"));
		} catch (RuntimeException e) {
			LOGGER.infof("No specific signatory port configured. Will use the default {}.", signatoryPort);
		}
	}

	private void initializeIssuerDid() {
		try {
			issuerDid = System.getenv("VCISSUER_ISSUER_DID");
			validateDid(issuerDid);
		} catch (NullPointerException e) {
			LOGGER.info("No issuer did provided, will create one.");
			issuerDid = waltIdClient.createDid();
		}
	}

	private void validateDid(String issuerDid) {
		waltIdClient.getDidDocument(issuerDid)
				.orElseThrow(() -> new VCIssuerException("The configured DID does not exist or is not valid."));
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
