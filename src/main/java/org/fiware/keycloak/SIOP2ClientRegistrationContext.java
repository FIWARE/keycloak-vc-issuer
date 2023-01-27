package org.fiware.keycloak;

import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientregistration.AbstractClientRegistrationContext;
import org.keycloak.services.clientregistration.ClientRegistrationProvider;

/**
 * Empty registration context to fulfill client-registration integration.
 */
public class SIOP2ClientRegistrationContext extends AbstractClientRegistrationContext {

	public SIOP2ClientRegistrationContext(KeycloakSession session,
			ClientRepresentation client,
			ClientRegistrationProvider provider) {
		super(session, client, provider);
	}
}
