package org.fiware.keycloak.mappers;

import com.danubetech.verifiablecredentials.VerifiableCredential;
import org.fiware.keycloak.SIOP2LoginProtocolFactory;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class SIOP2SubjectIdMapper extends SIOP2Mapper {

	public static final String MAPPER_ID = "siop-2-subject-id-mapper";
	public static final String ID_KEY = "subjectIdProperty";

	public SIOP2SubjectIdMapper(ProtocolMapperModel mapperModel) {
		super(mapperModel);
	}

	public static ProtocolMapperModel create(String name, String subjectId) {
		var mapperModel = new ProtocolMapperModel();
		mapperModel.setName(name);
		Map<String, String> configMap = new HashMap<>();
		configMap.put(ID_KEY, subjectId);
		configMap.put(SUPPORTED_CREDENTIALS_KEY, "VerifiableCredential");
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
		claims.put("id", mapperModel.getConfig().getOrDefault(ID_KEY, String.format("urn:uuid:%s", UUID.randomUUID())));
	}

	@Override public String getDisplayType() {
		return "CredentialSubject ID Mapper";
	}

	@Override public String getHelpText() {
		return "Assigns a subject ID to the credentials subject. If no specific id is configured, a randomly generated one is used.";
	}

	@Override public List<ProviderConfigProperty> getConfigProperties() {
		return List.of();
	}

	@Override public String getId() {
		return MAPPER_ID;
	}
}
