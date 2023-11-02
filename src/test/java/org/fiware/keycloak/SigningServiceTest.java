package org.fiware.keycloak;

import com.danubetech.verifiablecredentials.CredentialSubject;
import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.danubetech.verifiablecredentials.jsonld.VerifiableCredentialContexts;
import foundation.identity.jsonld.JsonLDUtils;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.util.Map;

public class SigningServiceTest {

	@Test
	public void testJWT() throws Exception {
		JWTSigningService signingService = new JWTSigningService(
				"/home/stefanwiedemann/git/fiware/keycloak-vc-issuer/src/test/resources/tls-test.key",
				AlgorithmType.RSA);
		signingService.signCredential(new VerifiableCredential());
	}

	@Test
	public void testLD() throws Exception {
		LDSigningService signingService = new LDSigningService(
				"/home/stefanwiedemann/git/fiware/keycloak-vc-issuer/src/test/resources/tls-test.key",
				AlgorithmType.RSA, Clock.systemUTC());

		CredentialSubject credentialSubject = CredentialSubject.builder()
				.id(URI.create("did:example:ebfeb1f712ebc6f1c276e12ec21"))
				.claims(Map.of("my", "claim"))
				.build();
		VerifiableCredential verifiableCredential = VerifiableCredential.builder()
				.context(VerifiableCredentialContexts.JSONLD_CONTEXT_W3C_2018_CREDENTIALS_EXAMPLES_V1)
				.type("UniversityDegreeCredential")
				.id(URI.create("http://example.edu/credentials/3732"))
				.issuer(URI.create("did:example:76e12ec712ebc6f1c221ebfeb1f"))
				.issuanceDate(JsonLDUtils.stringToDate("2019-06-16T18:56:59Z"))
				.expirationDate(JsonLDUtils.stringToDate("2019-06-17T18:56:59Z"))
				.credentialSubject(credentialSubject)
				.build();

		VerifiableCredential vc = signingService.signCredential(verifiableCredential);
	}
}