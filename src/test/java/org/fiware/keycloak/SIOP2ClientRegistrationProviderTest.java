package org.fiware.keycloak;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.ErrorResponseException;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.fiware.keycloak.SIOP2ClientRegistrationProvider.EXPIRY_IN_MIN;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;

@Slf4j
public class SIOP2ClientRegistrationProviderTest {

	@DisplayName("Validate clientRepresentation to fit the requirements of a SIOP-2 client.")
	@ParameterizedTest
	@MethodSource("provideClientRepresentations")
	public void testValidate(ClientRepresentation toTest, ExpectedResult<Boolean> expectedResult) {
		try {
			SIOP2ClientRegistrationProvider.validate(toTest);
		} catch (ErrorResponseException e) {
			if (expectedResult.getExpectedResult()) {
				fail(expectedResult.getMessage());
			}
			return;
		}
		if (!expectedResult.getExpectedResult()) {
			fail(expectedResult.getMessage());
		}
	}

	@DisplayName("Validate that SIOP-2 clients are properly translated to ClientRepresentations")
	@ParameterizedTest
	@MethodSource("provideSIOP2Clients")
	public void testToClientRepresentation(SIOP2Client toTest, ExpectedResult<ClientRepresentation> expectedResult)
			throws IllegalAccessException {
		String errorMessage = compare(expectedResult.getExpectedResult(),
				SIOP2ClientRegistrationProvider.toClientRepresentation(toTest));
		assertNull(errorMessage, String.format("%s - %s",
				expectedResult.getMessage(), errorMessage));
	}

	private static Stream<Arguments> provideSIOP2Clients() {
		return Stream.of(
				Arguments.of(SIOP2Client.builder().clientDid("did:test:did").build(),
						new ExpectedResult(getClientRepresentation("did:test:did"),
								"A valid client should have been created.")),
				Arguments.of(SIOP2Client.builder().clientDid("did:test:did").description("my desc").build(),
						new ExpectedResult(getClientRepresentation("did:test:did", null, "my desc", null),
								"A valid client should have been created.")),
				Arguments.of(
						SIOP2Client.builder().clientDid("did:test:did").name("my name").description("my desc").build(),
						new ExpectedResult(getClientRepresentation("did:test:did", "my name", "my desc", null),
								"A valid client should have been created.")),
				Arguments.of(SIOP2Client.builder().clientDid("did:test:did")
								.supportedVCTypes("PacketDeliveryService,SomethingFancy").build(),
						new ExpectedResult(getClientRepresentation("did:test:did", null, null,
								Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES,
										"PacketDeliveryService,SomethingFancy")),
								"A valid client should have been created.")),
				Arguments.of(SIOP2Client.builder().clientDid("did:test:did")
								.supportedVCTypes("PacketDeliveryService,SomethingFancy")
								.additionalClaims(Map.of("additional", "claim", "another", "one"))
								.build(),
						new ExpectedResult(getClientRepresentation("did:test:did", null, null,
								Map.of(
										"vc_another", "one",
										"vc_additional", "claim",
										SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES,
										"PacketDeliveryService,SomethingFancy")),
								"A valid client should have been created.")),
				Arguments.of(SIOP2Client.builder().clientDid("did:test:did")
								.supportedVCTypes("PacketDeliveryService,SomethingFancy")
								.expiryInMin(1000l)
								.additionalClaims(Map.of("additional", "claim", "another", "one"))
								.build(),
						new ExpectedResult(getClientRepresentation("did:test:did", null, null,
								Map.of(
										"vc_another", "one",
										"vc_additional", "claim",
										EXPIRY_IN_MIN, "1000",
										SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES,
										"PacketDeliveryService,SomethingFancy")),
								"A valid client should have been created."))
		);
	}

	private static Stream<Arguments> provideClientRepresentations() {
		return Stream.of(
				Arguments.of(getClientRepresentation("invalidId"),
						new ExpectedResult(false, "Only valid DIDs are accepted.")),
				Arguments.of(getClientRepresentation(null), new ExpectedResult(false, "Null is not a valid DID.")),
				Arguments.of(getClientRepresentation("did-key-mykey"),
						new ExpectedResult(false, "Only valid DIDs are accepted.")),
				Arguments.of(getClientRepresentation("did:key:mykey"),
						new ExpectedResult(true, "Valid DIDs should be accepted."))
		);
	}

	private static ClientRepresentation getClientRepresentation(String clientId) {
		return getClientRepresentation(clientId, null, null, null);
	}

	private static ClientRepresentation getClientRepresentation(String clientId, String name, String description,
			Map<String, String> additionalClaims) {
		ClientRepresentation cr = new ClientRepresentation();
		cr.setClientId(clientId);
		cr.setId(clientId);
		cr.setProtocol(SIOP2LoginProtocolFactory.PROTOCOL_ID);
		cr.setAttributes(additionalClaims);
		cr.setDescription(description);
		cr.setName(name);

		return cr;
	}

	// client representation does not implement equals and serialization does not gurantee order of maps and lists, thus
	// we use reflections to compare them
	private static String compare(ClientRepresentation c1, ClientRepresentation c2) throws IllegalAccessException {

		Optional<Field> notEqualsField = Arrays.stream(ClientRepresentation.class.getDeclaredFields())
				.peek(field -> field.setAccessible(true))
				.filter(field -> {
					try {
						var v1 = field.get(c1);
						var v2 = field.get(c2);
						if (v1 == null && v2 == null) {
							return false;
						}
						return !v1.equals(v2);
					} catch (IllegalAccessException e) {
						log.warn("Was not able to access fiel.", e);
						return true;
					}
				}).findFirst();
		if (notEqualsField.isPresent()) {
			Field f = notEqualsField.get();
			var v1 = f.get(c1);
			var v2 = f.get(c2);
			return String.format("Field %s does not match. V1: %s V2: %s", notEqualsField.toString(), v1, v2);
		}
		return null;
	}


}