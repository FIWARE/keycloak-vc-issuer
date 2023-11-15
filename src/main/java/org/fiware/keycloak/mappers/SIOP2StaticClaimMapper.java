package org.fiware.keycloak.mappers;

import com.danubetech.verifiablecredentials.VerifiableCredential;
import org.fiware.keycloak.SIOP2LoginProtocolFactory;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SIOP2StaticClaimMapper extends SIOP2Mapper {

	public static final String MAPPER_ID = "siop-2-static-claim-mapper";

	public static final String SUBJECT_PROPERTY_CONFIG_KEY = "subjectProperty";
	public static final String STATIC_CLAIM_KEY = "staticValue";

	public SIOP2StaticClaimMapper(ProtocolMapperModel mapperModel) {
		super(mapperModel);
	}

	public static ProtocolMapperModel create(String mapperName, String propertyName, String value) {
		var mapperModel = new ProtocolMapperModel();
		mapperModel.setName(mapperName);
		Map<String, String> configMap = new HashMap<>();
		configMap.put(SUBJECT_PROPERTY_CONFIG_KEY, propertyName);
		configMap.put(STATIC_CLAIM_KEY, value);
		mapperModel.setConfig(configMap);
		mapperModel.setProtocol(SIOP2LoginProtocolFactory.PROTOCOL_ID);
		mapperModel.setProtocolMapper(MAPPER_ID);
		return mapperModel;
	}

	@Override public void setClaimsForCredential(VerifiableCredential.Builder credentialBuilder,
			UserSessionModel userSessionModel) {
		// nothing to do for the mapper.
	}

	@Override public void setClaimsForSubject(Map<String, Object> claims, UserSessionModel userSessionModel) {
		String propertyName = mapperModel.getConfig().get(SUBJECT_PROPERTY_CONFIG_KEY);
		String staticValue = mapperModel.getConfig().get(STATIC_CLAIM_KEY);
		claims.put(propertyName, staticValue);
	}

	@Override public String getDisplayType() {
		return "Static Claim Mapper";
	}

	@Override public String getHelpText() {
		return "Allows to set static values for the credential subject.";
	}

	@Override public List<ProviderConfigProperty> getConfigProperties() {
		return List.of();
	}

	@Override public String getId() {
		return MAPPER_ID;
	}
}
