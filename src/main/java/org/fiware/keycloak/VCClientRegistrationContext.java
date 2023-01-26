package org.fiware.keycloak;

import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientregistration.AbstractClientRegistrationContext;
import org.keycloak.services.clientregistration.ClientRegistrationProvider;

public class VCClientRegistrationContext extends AbstractClientRegistrationContext {

	public VCClientRegistrationContext(KeycloakSession session,
			ClientRepresentation client,
			ClientRegistrationProvider provider) {
		super(session, client, provider);
	}
}
