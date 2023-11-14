package org.fiware.keycloak.mappers;

import com.danubetech.verifiablecredentials.VerifiableCredential;
import org.fiware.keycloak.SIOP2LoginProtocolFactory;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class SIOP2UserAttributeMapper extends SIOP2Mapper {

	public static final String MAPPER_ID = "siop-2-user-attribute-mapper";
	public static final String SUBJECT_PROPERTY_CONFIG_KEY = "subject-property";
	public static final String USER_ATTRIBUTE_KEY = "user-attribute";
	public static final String AGGREGATE_ATTRIBUTES_KEY = "aggregate-attributes";

	public SIOP2UserAttributeMapper(ProtocolMapperModel mapperModel) {
		super(mapperModel);
	}

	@Override public void setClaimsForCredential(VerifiableCredential.Builder credentialBuilder,
			UserSessionModel userSessionModel) {
		// nothing to do for the mapper.
	}

	@Override public void setClaimsForSubject(Map<String, Object> claims, UserSessionModel userSessionModel) {
		String propertyName = mapperModel.getConfig().get(SUBJECT_PROPERTY_CONFIG_KEY);
		String userAttribute = mapperModel.getConfig().get(USER_ATTRIBUTE_KEY);
		boolean aggregateAttributes = Optional.ofNullable(mapperModel.getConfig().get(AGGREGATE_ATTRIBUTES_KEY))
				.map(Boolean::parseBoolean).orElse(false);
		Collection<String> attributes =
				KeycloakModelUtils.resolveAttribute(userSessionModel.getUser(), userAttribute,
						aggregateAttributes);
		attributes.removeAll(Collections.singleton(null));
		if (!attributes.isEmpty()) {
			claims.put(propertyName, String.join(",", attributes));
		}
	}

	public static ProtocolMapperModel create(String mapperName, String userAttribute, String propertyName,
			boolean aggregateAttributes) {
		var mapperModel = new ProtocolMapperModel();
		mapperModel.setName(mapperName);
		Map<String, String> configMap = new HashMap<>();
		configMap.put(SUBJECT_PROPERTY_CONFIG_KEY, propertyName);
		configMap.put(USER_ATTRIBUTE_KEY, userAttribute);
		configMap.put(AGGREGATE_ATTRIBUTES_KEY, Boolean.toString(aggregateAttributes));
		mapperModel.setConfig(configMap);
		mapperModel.setProtocol(SIOP2LoginProtocolFactory.PROTOCOL_ID);
		mapperModel.setProtocolMapper(MAPPER_ID);
		return mapperModel;
	}

	@Override public String getDisplayType() {
		return "User Attribute Mapper";
	}

	@Override public String getHelpText() {
		return "Maps user attributes to credential subject properties.";
	}

	@Override public List<ProviderConfigProperty> getConfigProperties() {
		return List.of();
	}

	@Override public String getId() {
		return MAPPER_ID;
	}
}
