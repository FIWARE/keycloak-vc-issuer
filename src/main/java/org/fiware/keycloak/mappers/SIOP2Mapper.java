package org.fiware.keycloak.mappers;

import com.danubetech.verifiablecredentials.CredentialSubject;
import com.danubetech.verifiablecredentials.VerifiableCredential;
import lombok.RequiredArgsConstructor;
import org.fiware.keycloak.SIOP2LoginProtocolFactory;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapper;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

@RequiredArgsConstructor
public abstract class SIOP2Mapper implements ProtocolMapper {
	protected static final String SUPPORTED_CREDENTIALS_KEY = "supportedCredentialTypes";

	protected final ProtocolMapperModel mapperModel;

	@Override public String getProtocol() {
		return SIOP2LoginProtocolFactory.PROTOCOL_ID;
	}

	@Override public ProtocolMapper create(KeycloakSession session) {
		throw new SIOP2MapperException("UNSUPPORTED METHOD");
	}

	@Override public String getDisplayCategory() {
		return "SIOP-2 Mapper";
	}

	@Override public void init(Config.Scope scope) {
	}

	@Override public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
	}

	@Override public void close() {
	}

	/**
	 * Checks if the mapper supports the given credential type. Allows to configure them not only per client, but also per VC Type.
	 *
	 * @param credentialType type of the VerifiableCredential that should be checked
	 * @return true if it is supported
	 */
	public boolean isTypeSupported(String credentialType) {
		var optionalTypes = Optional.ofNullable(mapperModel.getConfig().get(SUPPORTED_CREDENTIALS_KEY));
		if (optionalTypes.isEmpty()) {
			return false;
		}
		return Arrays.asList(optionalTypes.get().split(",")).contains(credentialType);
	}

	/**
	 * Set the claims to credential, like f.e. the context
	 */
	public abstract void setClaimsForCredential(VerifiableCredential.Builder credentialBuilder,
			UserSessionModel userSessionModel);

	/**
	 * Set the claims to the credential subject.
	 */
	public abstract void setClaimsForSubject(Map<String, Object> claims,
			UserSessionModel userSessionModel);

}
