package org.fiware.keycloak;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

public abstract class SigningService<T> implements VCSigningService<T> {

	private static final Logger LOGGER = Logger.getLogger(SigningService.class);

	protected final KeyPair signingKey;

	protected SigningService(String keyPath) {

		this.signingKey = parsePem(loadPrivateKeyString(keyPath));
	}

	protected String loadPrivateKeyString(String keyPath) {
		Path keyFilePath = Paths.get(keyPath);
		try {
			return Files.readString(keyFilePath);
		} catch (IOException e) {
			LOGGER.errorf("Was not able to read the private key from %s", keyPath);
			throw new SigningServiceException("Was not able to read private key. Cannot initiate the SigningService.",
					e);
		}
	}

	protected KeyPair parsePem(String keyString) {
		PEMParser pemParser = new PEMParser(new StringReader(keyString));
		List<Object> parsedObjects = new ArrayList<>();
		try {
			var currentObject = pemParser.readObject();
			while (currentObject != null) {
				parsedObjects.add(currentObject);
				currentObject = pemParser.readObject();
			}
		} catch (IOException e) {
			throw new SigningServiceException("Was not able to parse the key-pem");
		}
		SubjectPublicKeyInfo publicKeyInfo = null;
		PrivateKeyInfo privateKeyInfo = null;
		for (Object parsedObject : parsedObjects) {
			if (parsedObject instanceof SubjectPublicKeyInfo spki) {
				publicKeyInfo = spki;
			} else if (parsedObject instanceof PrivateKeyInfo pki) {
				privateKeyInfo = pki;
			} else if (parsedObject instanceof PEMKeyPair pkp) {
				publicKeyInfo = pkp.getPublicKeyInfo();
				privateKeyInfo = pkp.getPrivateKeyInfo();
			}
		}
		if (privateKeyInfo == null) {
			throw new SigningServiceException("Was not able to read a private key.");
		}
		PublicKey publicKey = null;
		if (publicKeyInfo != null) {
			try {
				KeyFactory keyFactory = KeyFactory.getInstance(publicKeyInfo.getAlgorithm().getAlgorithm().getId());
				publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyInfo.getEncoded()));
			} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
				throw new SigningServiceException("Was not able to get the public key.", e);
			}
		}
		try {
			KeyFactory privateKeyFactory = KeyFactory.getInstance(
					privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm().getId());
			PrivateKey privateKey = privateKeyFactory.generatePrivate(
					new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded()));
			return new KeyPair(publicKey, privateKey);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			throw new SigningServiceException("Was not able to get the public key.", e);
		}
	}

}
