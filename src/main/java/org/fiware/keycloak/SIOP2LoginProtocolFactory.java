package org.fiware.keycloak;

import com.google.auto.service.AutoService;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.LoginProtocolFactory;
import org.keycloak.representations.idm.ClientRepresentation;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * This factory is required to get the capability of creating {@link VCClientModel} using the SIOP-2 protocol.
 * Clients cannot be created without a matching protocol. We do not support logging into keycloak with it, nor any other
 * "native" functionality, thus we don't implement anything beside the
 */
@AutoService(LoginProtocolFactory.class)
public class SIOP2LoginProtocolFactory implements LoginProtocolFactory {

	private static final Logger LOGGER = Logger.getLogger(SIOP2LoginProtocolFactory.class);
	public static final String PROTOCOL_ID = "SIOP-2";

	@Override public Map<String, ProtocolMapperModel> getBuiltinMappers() {
		return new HashMap<>();
	}

	@Override public Object createProtocolEndpoint(RealmModel realm, EventBuilder event) {
		return null;
	}

	@Override public void createDefaultClientScopes(RealmModel newRealm, boolean addScopesToExistingClients) {
	}

	@Override public void setupClientDefaults(ClientRepresentation rep, ClientModel newClient) {

		LOGGER.info("Set defaults");
		// validate before setting the defaults
		VCClientRegistrationProvider.validate(rep);
		newClient.setAttribute(VCClientRegistrationProvider.SUPPORTED_VC_TYPES, Optional.ofNullable(rep.getAttributes())
				.map(attrs -> attrs.get(VCClientRegistrationProvider.SUPPORTED_VC_TYPES))
				.orElse("VerifiableCredential"));
	}

	@Override public LoginProtocol create(KeycloakSession session) {
		return new SIOP2LoginProtocol(session);
	}

	@Override public void init(Config.Scope config) {
	}

	@Override public void postInit(KeycloakSessionFactory factory) {

	}

	@Override public void close() {

	}

	@Override public String getId() {
		return PROTOCOL_ID;
	}
}
