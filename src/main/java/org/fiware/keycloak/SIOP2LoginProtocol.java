package org.fiware.keycloak;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Empty implementation of the SIOP2LoginProtocl. Its required to be available for integration with the client-registration.
 * Since we do not support any additional functionality(like logging into Keycloak with SIOP-2), its an empty default
 * implementation.
 */
public class SIOP2LoginProtocol implements LoginProtocol {

	public SIOP2LoginProtocol(KeycloakSession session) {
	}

	@Override public SIOP2LoginProtocol setSession(KeycloakSession session) {
		return this;
	}

	@Override public SIOP2LoginProtocol setRealm(RealmModel realm) {
		return this;
	}

	@Override public LoginProtocol setUriInfo(UriInfo uriInfo) {
		return null;
	}

	@Override public LoginProtocol setHttpHeaders(HttpHeaders httpHeaders) {
		return null;
	}

	@Override
	public SIOP2LoginProtocol setEventBuilder(EventBuilder event) {
		return this;
	}

	@Override public Response authenticated(AuthenticationSessionModel authSession, UserSessionModel userSession,
			ClientSessionContext clientSessionCtx) {
		return null;
	}

	@Override public Response sendError(AuthenticationSessionModel authSession, Error error) {
		return null;
	}

	@Override public Response backchannelLogout(UserSessionModel userSession,
			AuthenticatedClientSessionModel clientSession) {
		return null;
	}

	@Override public Response frontchannelLogout(UserSessionModel userSession,
			AuthenticatedClientSessionModel clientSession) {
		return null;
	}

	@Override public Response finishBrowserLogout(UserSessionModel userSession,
			AuthenticationSessionModel logoutSession) {
		return null;
	}

	@Override public boolean requireReauthentication(UserSessionModel userSession,
			AuthenticationSessionModel authSession) {
		return false;
	}

	@Override public void close() {
		// nothing to close, just fulfilling the interface.
	}
}
