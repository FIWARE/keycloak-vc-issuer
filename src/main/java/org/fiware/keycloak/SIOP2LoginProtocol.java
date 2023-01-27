package org.fiware.keycloak;

import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

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

	@Override
	public SIOP2LoginProtocol setUriInfo(UriInfo uriInfo) {
		return this;
	}

	@Override
	public SIOP2LoginProtocol setHttpHeaders(HttpHeaders headers) {
		return this;
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
