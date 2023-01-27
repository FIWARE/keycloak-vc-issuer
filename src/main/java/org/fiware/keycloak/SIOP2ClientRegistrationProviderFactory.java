package org.fiware.keycloak;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.clientregistration.ClientRegistrationProvider;
import org.keycloak.services.clientregistration.ClientRegistrationProviderFactory;

/**
 * Empty implementation of the {@link ClientRegistrationProviderFactory} to integrate the SIOP-2 protocol with
 * Keycloaks client-registration.
 */
@AutoService(ClientRegistrationProviderFactory.class)
public class SIOP2ClientRegistrationProviderFactory implements ClientRegistrationProviderFactory {

	@Override public ClientRegistrationProvider create(KeycloakSession session) {
		return new SIOP2ClientRegistrationProvider(session);
	}

	@Override public void init(Config.Scope config) {
		// no config required
	}

	@Override public void postInit(KeycloakSessionFactory factory) {
		// nothing to do post init
	}

	@Override public void close() {
		// no resources to close
	}

	@Override public String getId() {
		return SIOP2LoginProtocolFactory.PROTOCOL_ID;
	}
}
