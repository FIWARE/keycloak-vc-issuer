package org.fiware.keycloak;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.clientregistration.ClientRegistrationProvider;
import org.keycloak.services.clientregistration.ClientRegistrationProviderFactory;

@AutoService(ClientRegistrationProviderFactory.class)
public class VCClientRegistrationProviderFactory implements ClientRegistrationProviderFactory {

	@Override public ClientRegistrationProvider create(KeycloakSession session) {
		return new VCClientRegistrationProvider(session);
	}

	@Override public void init(Config.Scope config) {

	}

	@Override public void postInit(KeycloakSessionFactory factory) {

	}

	@Override public void close() {

	}

	@Override public String getId() {
		return SIOP2LoginProtocolFactory.PROTOCOL_ID;
	}
}
