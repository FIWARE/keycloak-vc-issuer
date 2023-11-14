package org.fiware.keycloak.mappers;

import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.fiware.keycloak.SIOP2LoginProtocolFactory;
import org.fiware.keycloak.model.Role;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.provider.ProviderConfigProperty;

import javax.validation.constraints.NotNull;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class SIOP2TargetRoleMapper extends SIOP2Mapper {

	private static final Logger LOGGER = Logger.getLogger(SIOP2TargetRoleMapper.class);
	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	public static final String MAPPER_ID = "siop-2-target-role-mapper";
	public static final String SUBJECT_PROPERTY_CONFIG_KEY = "subject-property";
	public static final String CLIENT_CONFIG_KEY = "client";

	public SIOP2TargetRoleMapper(ProtocolMapperModel mapperModel) {
		super(mapperModel);
	}

	@Override public String getDisplayType() {
		return "Target-Role Mapper";
	}

	@Override public String getHelpText() {
		return "Map the assigned role to the credential subject, providing the client id as the target.";
	}

	@Override public List<ProviderConfigProperty> getConfigProperties() {
		return List.of();
	}

	public static ProtocolMapperModel create(String clientId, String name) {
		var mapperModel = new ProtocolMapperModel();
		mapperModel.setName(name);
		Map<String, String> configMap = new HashMap<>();
		configMap.put(SUBJECT_PROPERTY_CONFIG_KEY, "roles");
		configMap.put(CLIENT_CONFIG_KEY, clientId);
		mapperModel.setConfig(configMap);
		mapperModel.setProtocol(SIOP2LoginProtocolFactory.PROTOCOL_ID);
		mapperModel.setProtocolMapper(MAPPER_ID);
		return mapperModel;
	}

	@Override public String getId() {
		return MAPPER_ID;
	}

	@Override
	public void setClaimsForCredential(VerifiableCredential.Builder credentialBuilder,
			UserSessionModel userSessionModel) {
		// nothing to do for the mapper.
	}

	@Override
	public void setClaimsForSubject(Map<String, Object> claims,
			UserSessionModel userSessionModel) {
		String client = mapperModel.getConfig().get(CLIENT_CONFIG_KEY);
		String propertyName = mapperModel.getConfig().get(SUBJECT_PROPERTY_CONFIG_KEY);
		LOGGER.infof("Client is %s", client);
		ClientModel clientModel = userSessionModel.getRealm().getClientByClientId(client);
		if (clientModel == null || !clientModel.getProtocol().equals(SIOP2LoginProtocolFactory.PROTOCOL_ID)) {
			return;
		}

		ClientRoleModel clientRoleModel = new ClientRoleModel(clientModel.getClientId(),
				userSessionModel.getUser().getClientRoleMappingsStream(clientModel).toList());
		Role rolesClaim = toRolesClaim(clientRoleModel);
		if (rolesClaim.getNames().isEmpty()) {
			return;
		}
		var modelMap = OBJECT_MAPPER.convertValue(toRolesClaim(clientRoleModel), Map.class);

		if (claims.containsKey(propertyName)) {
			if (claims.get(propertyName) instanceof Set rolesProperty) {
				rolesProperty.add(modelMap);
				claims.put(propertyName, rolesProperty);
			} else {
				LOGGER.warnf("Incompatible types for property %s. The mapper will not set the roles for client %s",
						propertyName, client);
			}
		} else {
			// needs to be mutable
			Set roles = new HashSet();
			roles.add(modelMap);
			claims.put(propertyName, roles);
		}
	}

	@NotNull
	private Role toRolesClaim(ClientRoleModel crm) {
		Set<String> roleNames = crm
				.getRoleModels()
				.stream()
				.map(RoleModel::getName)
				.collect(Collectors.toSet());
		return new Role(roleNames, crm.getClientId());
	}

	@Getter
	@RequiredArgsConstructor
	private static class ClientRoleModel {
		private final String clientId;
		private final List<RoleModel> roleModels;
	}
}
