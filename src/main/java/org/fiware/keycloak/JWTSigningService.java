package org.fiware.keycloak;

import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.danubetech.verifiablecredentials.jwt.JwtVerifiableCredential;
import com.danubetech.verifiablecredentials.jwt.ToJwtConverter;
import com.nimbusds.jose.JOSEException;
import org.bitcoinj.core.ECKey;
import org.jboss.logging.Logger;

public class JWTSigningService extends SigningService<String> {

	private static final Logger LOGGER = Logger.getLogger(JWTSigningService.class);

	public JWTSigningService(String keyPath,
			AlgorithmType algorithmType) {
		super(keyPath, algorithmType);
	}

	@Override
	public String signCredential(VerifiableCredential verifiableCredential) {
		JwtVerifiableCredential jwtVerifiableCredential = ToJwtConverter.toJwtVerifiableCredential(
				verifiableCredential);
		try {

			return switch (algorithmType) {
				case RSA -> {
					String concreteAlgorithm = signingKey.getPrivate().getAlgorithm();
					if (concreteAlgorithm.equalsIgnoreCase("rs256")) {
						yield jwtVerifiableCredential.sign_RSA_RS256(signingKey);
					} else {
						yield jwtVerifiableCredential.sign_RSA_PS256(signingKey);
					}
				}
				case ECDSA_Secp256k1 -> jwtVerifiableCredential.sign_secp256k1_ES256K(
						ECKey.fromPrivate(signingKey.getPrivate().getEncoded()));
				case EdDSA_Ed25519 -> jwtVerifiableCredential.sign_Ed25519_EdDSA(signingKey.getPrivate().getEncoded());

			};
		} catch (JOSEException e) {
			throw new SigningServiceException("Was not able to sign the credential.", e);
		}
	}
}