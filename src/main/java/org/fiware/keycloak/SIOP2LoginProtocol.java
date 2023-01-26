package org.fiware.keycloak;

import org.jboss.logging.Logger;
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

public class SIOP2LoginProtocol implements LoginProtocol {

	private KeycloakSession session;
	private RealmModel realm;
	private UriInfo uriInfo;
	private HttpHeaders headers;
	private EventBuilder event;

	public SIOP2LoginProtocol(KeycloakSession session) {
		this.session = session;
	}

	@Override public SIOP2LoginProtocol setSession(KeycloakSession session) {
		this.session = session;
		return this;
	}

	@Override public SIOP2LoginProtocol setRealm(RealmModel realm) {
		this.realm = realm;
		return this;
	}

	@Override
	public SIOP2LoginProtocol setUriInfo(UriInfo uriInfo) {
		this.uriInfo = uriInfo;
		return this;
	}

	@Override
	public SIOP2LoginProtocol setHttpHeaders(HttpHeaders headers) {
		this.headers = headers;
		return this;
	}

	@Override
	public SIOP2LoginProtocol setEventBuilder(EventBuilder event) {
		this.event = event;
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

	}
}
