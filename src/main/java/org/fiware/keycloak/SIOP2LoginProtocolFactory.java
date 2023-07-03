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
import java.util.Objects;
import java.util.Optional;

/**
 * This factory is required to get the capability of creating {@link SIOP2ClientModel} using the SIOP-2 protocol.
 * Clients cannot be created without a matching protocol. We do not support logging into keycloak with it, nor any other
 * "native" functionality, thus we don't implement anything beside the
 */
@AutoService(LoginProtocolFactory.class)
public class SIOP2LoginProtocolFactory implements LoginProtocolFactory {

	public static final String PROTOCOL_ID = "SIOP-2";

	@Override public Map<String, ProtocolMapperModel> getBuiltinMappers() {
		return new HashMap<>();
	}

	@Override public Object createProtocolEndpoint(KeycloakSession keycloakSession, EventBuilder eventBuilder) {
		return null;
	}

	@Override public void createDefaultClientScopes(RealmModel newRealm, boolean addScopesToExistingClients) {
		// no default scopes required
	}

	@Override public void setupClientDefaults(ClientRepresentation rep, ClientModel newClient) {

		// validate before setting the defaults
		SIOP2ClientRegistrationProvider.validate(rep);
		rep.setBearerOnly(true);
	}

	@Override public LoginProtocol create(KeycloakSession session) {
		return new SIOP2LoginProtocol(session);
	}

	@Override public void init(Config.Scope config) {
		// no config required
	}

	@Override public void postInit(KeycloakSessionFactory factory) {
		// nothing to do.
	}

	@Override public void close() {
		// nothing to close.
	}

	@Override public String getId() {
		return PROTOCOL_ID;
	}
}
