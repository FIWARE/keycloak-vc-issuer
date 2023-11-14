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

import java.util.Map;

@RequiredArgsConstructor
public abstract class SIOP2Mapper implements ProtocolMapper {

	protected final ProtocolMapperModel mapperModel;

	@Override public String getProtocol() {
		return SIOP2LoginProtocolFactory.PROTOCOL_ID;
	}

	@Override public ProtocolMapper create(KeycloakSession session) {
		throw new RuntimeException("UNSUPPORTED METHOD");
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
