package org.fiware.keycloak;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auto.service.AutoService;
import org.fiware.keycloak.mappers.SIOP2SubjectIdMapper;
import org.fiware.keycloak.mappers.SIOP2TargetRoleMapper;
import org.fiware.keycloak.mappers.SIOP2UserAttributeMapper;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.LoginProtocolFactory;
import org.keycloak.representations.idm.ClientRepresentation;

import java.util.HashMap;
import java.util.Map;

/**
 * This factory is required to get the capability of creating {@link SIOP2ClientModel} using the SIOP-2 protocol.
 * Clients cannot be created without a matching protocol. We do not support logging into keycloak with it, nor any other
 * "native" functionality, thus we don't implement anything beside the
 */
@AutoService(LoginProtocolFactory.class)
public class SIOP2LoginProtocolFactory implements LoginProtocolFactory {

	private static final Logger LOGGER = Logger.getLogger(SIOP2LoginProtocolFactory.class);

	public static final String PROTOCOL_ID = "SIOP-2";

	private static final String CLIENT_ROLES_MAPPER = "client-roles";
	private static final String SUBJECT_ID_MAPPER = "subject-id";
	private static final String USERNAME_MAPPER = "username";
	private static final String EMAIL_MAPPER = "email";
	private static final String LAST_NAME_MAPPER = "last-name";
	private static final String FIRST_NAME_MAPPER = "first-name";

	private Map<String, ProtocolMapperModel> builtins = new HashMap<>();

	@Override public void init(Config.Scope config) {

		builtins.put(CLIENT_ROLES_MAPPER,
				SIOP2TargetRoleMapper.create("id", "client roles"));
		builtins.put(SUBJECT_ID_MAPPER,
				SIOP2SubjectIdMapper.create("subject id", "id"));
		builtins.put(USERNAME_MAPPER,
				SIOP2UserAttributeMapper.create(USERNAME_MAPPER, "username", "username", false));
		builtins.put(EMAIL_MAPPER,
				SIOP2UserAttributeMapper.create(EMAIL_MAPPER, "email", "email", false));
		builtins.put(FIRST_NAME_MAPPER,
				SIOP2UserAttributeMapper.create(FIRST_NAME_MAPPER, "firstName", "firstName", false));
		builtins.put(LAST_NAME_MAPPER,
				SIOP2UserAttributeMapper.create(LAST_NAME_MAPPER, "lastName", "familyName", false));
	}

	@Override public void postInit(KeycloakSessionFactory factory) {

	}

	@Override public void close() {

	}

	@Override
	public Map<String, ProtocolMapperModel> getBuiltinMappers() {
		return builtins;
	}

	@Override
	public Object createProtocolEndpoint(KeycloakSession session, EventBuilder event) {
		return null;
	}

	@Override public void createDefaultClientScopes(RealmModel newRealm, boolean addScopesToExistingClients) {
		LOGGER.debugf("Create default scopes for realm %s", newRealm.getName());
		ClientScopeModel targetRolesScope = KeycloakModelUtils.getClientScopeByName(newRealm, "Siop2TargetRoleScope");
		if (targetRolesScope == null) {
			LOGGER.debug("Add target roles scope");
			targetRolesScope = newRealm.addClientScope("Siop2TargetRoleScope");
			targetRolesScope.setDescription(
					"SIOP-2 Target Role Scope, that adds the roles for all SIOP-2 clients to the credential subject.");
			targetRolesScope.setProtocol(PROTOCOL_ID);
			targetRolesScope.addProtocolMapper(builtins.get(CLIENT_ROLES_MAPPER));
			newRealm.addDefaultClientScope(targetRolesScope, false);
		}
		ClientScopeModel subjectIdModelScope = KeycloakModelUtils.getClientScopeByName(newRealm, "Siop2SubjectIdScope");
		if (subjectIdModelScope == null) {
			LOGGER.debug("Add subject id scope");
			subjectIdModelScope = newRealm.addClientScope("Siop2SubjectIdScope");
			subjectIdModelScope.setDescription(
					"SIOP-2 Subject Id Scope, that adds an id to the credential subject.");
			subjectIdModelScope.setProtocol(PROTOCOL_ID);
			subjectIdModelScope.addProtocolMapper(builtins.get(SUBJECT_ID_MAPPER));
			newRealm.addDefaultClientScope(subjectIdModelScope, true);
		}
		ClientScopeModel attributesScope = KeycloakModelUtils.getClientScopeByName(newRealm, "Siop2AttributesScope");
		if (attributesScope == null) {
			LOGGER.debug("Add user attributes scope");
			subjectIdModelScope = newRealm.addClientScope("Siop2AttributesScope");
			subjectIdModelScope.setDescription(
					"SIOP-2 User Attributes Scope, that adds various user attributes to the credentials subject.");
			subjectIdModelScope.setProtocol(PROTOCOL_ID);
			subjectIdModelScope.addProtocolMapper(builtins.get(USERNAME_MAPPER));
			subjectIdModelScope.addProtocolMapper(builtins.get(FIRST_NAME_MAPPER));
			subjectIdModelScope.addProtocolMapper(builtins.get(LAST_NAME_MAPPER));
			subjectIdModelScope.addProtocolMapper(builtins.get(EMAIL_MAPPER));
			newRealm.addDefaultClientScope(subjectIdModelScope, true);
		}

	}

	@Override
	public void setupClientDefaults(ClientRepresentation rep, ClientModel newClient) {
		// validate before setting the defaults
		SIOP2ClientRegistrationProvider.validate(rep);
	}

	@Override public LoginProtocol create(KeycloakSession session) {
		return new SIOP2LoginProtocol(session);
	}

	@Override public String getId() {
		return PROTOCOL_ID;
	}

}
