package org.fiware.keycloak.it;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.Response;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.awaitility.Awaitility;
import org.fiware.keycloak.ExpectedResult;
import org.fiware.keycloak.SIOP2LoginProtocolFactory;
import org.fiware.keycloak.it.model.CredentialObject;
import org.fiware.keycloak.it.model.CredentialSubject;
import org.fiware.keycloak.it.model.IssuerMetaData;
import org.fiware.keycloak.it.model.Role;
import org.fiware.keycloak.it.model.SupportedCredentialMetadata;
import org.fiware.keycloak.it.model.VerifiableCredential;
import org.fiware.keycloak.model.SupportedCredential;
import org.fiware.keycloak.model.TokenResponse;
import org.fiware.keycloak.model.walt.CredentialOfferURI;
import org.fiware.keycloak.oidcvc.model.CredentialIssuerVO;
import org.fiware.keycloak.oidcvc.model.CredentialResponseVO;
import org.fiware.keycloak.oidcvc.model.CredentialsOfferVO;
import org.fiware.keycloak.oidcvc.model.FormatVO;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.token.TokenManager;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import javax.ws.rs.ClientErrorException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.fiware.keycloak.VCIssuerRealmResourceProvider.GRANT_TYPE_PRE_AUTHORIZED_CODE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Slf4j
public class SIOP2IntegrationTest {

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	private static final String KEYCLOAK_ADDRESS = "http://localhost:8080";
	private static final String WALT_ID_CORE_ADDRESS = "http://localhost:7000";
	private static final String WALT_ID_SIGN_ADDRESS = "http://localhost:7001";

	private static final String TEST_CLIENT_ID_ONE = "did:key:z6Mkv4Lh9zBTPLoFhLHHMFJA7YAeVw5HFYZV8rkdfY9fNtm3";
	private static final String TEST_CLIENT_ID_TWO = "did:key:z6Mkp7DVYuruxmKxsy2Rb3kMnfHgZZpbWYnY9rodvVfky7uj";

	private static final String KEYCLOAK_ISSUER_DID = "did:key:z6MkqmaCT2JqdUtLeKah7tEVfNXtDXtQyj4yxEgV11Y5CqUa";

	private static final String MASTER_REALM = "master";
	private static final String TEST_REALM = "test";
	private static final String ADMIN_USERNAME = "admin";
	private static final String ADMIN_PASSWORD = "admin";
	private static final String USER_PASSWORD = "password";
	private static final String ADMIN_CLI_CLIENT_ID = "admin-cli";
	private static final String ACCOUNT_CONSOLE_CLIENT_ID = "account-console";

	private static final String TEST_CONSUMER_ROLE = "CONSUMER";
	private static final String TEST_CREATOR_ROLE = "CREATOR";

	private String issuerDid;

	@BeforeEach
	public void waitForInit() throws Exception {
		Awaitility.await().atMost(Duration.of(2, ChronoUnit.MINUTES)).until(() -> {
			HttpResponse<String> response = HttpClient.newHttpClient()
					.send(HttpRequest.newBuilder()
							.GET()
							.uri(URI.create(String.format("%s/v1/did", WALT_ID_CORE_ADDRESS)))
							.build(), HttpResponse.BodyHandlers.ofString());
			if (response.statusCode() == 200) {
				issuerDid = (String) OBJECT_MAPPER.readValue(response.body(), List.class).get(0);
				return true;
			}
			return false;
		});

		Awaitility.await().atMost(Duration.of(2, ChronoUnit.MINUTES)).until(() -> {
			HttpResponse<String> response = HttpClient.newHttpClient()
					.send(HttpRequest.newBuilder()
							.GET()
							.uri(URI.create(String.format("%s/v1/templates/BatteryPassAuthCredential", WALT_ID_SIGN_ADDRESS)))
							.build(), HttpResponse.BodyHandlers.ofString());
			if (response.statusCode() == 200) {
				return true;
			}
			return false;
		});

		// create the test realm
		createTestRealm();
		// required to access realm api without a frontend
		enableDirectAccessForAccountConsole();

	}

	@AfterEach
	public void cleanUp() {
		// always start clean
		deleteTestRealm();
	}

	@DisplayName("The provided key and did should have been successfully imported")
	@Test
	public void testImportSuccess() {
		assertEquals(KEYCLOAK_ISSUER_DID, issuerDid, "The preconfigured did should have been imported.");
	}

	@DisplayName("Retrieve issuer metadata.")
	@ParameterizedTest
	@MethodSource("provideClients")
	public void testMetadataRetrieval(List<Client> clients, ExpectedResult<IssuerMetaData> expectedResult)
			throws IOException, InterruptedException {
		clients.forEach(c -> assertClientCreation(c.getId(), c.getSupportedTypes()));

		HttpRequest.Builder requestBuilder = HttpRequest.newBuilder().GET();
		requestBuilder.uri(URI.create(
				String.format("%s/realms/%s/verifiable-credential/%s/.well-known/openid-credential-issuer",
						KEYCLOAK_ADDRESS,
						TEST_REALM,
						KEYCLOAK_ISSUER_DID)));
		HttpResponse<String> response = HttpClient.newHttpClient()
				.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());

		assertEquals(HttpStatus.SC_OK, response.statusCode(),
				expectedResult.getMessage());
		assertEquals(expectedResult.getExpectedResult(),
				OBJECT_MAPPER.readValue(response.body(), IssuerMetaData.class), expectedResult.getMessage());

	}

	public static Stream<Arguments> provideClients() throws MalformedURLException {
		return Stream.of(
				Arguments.of(List.of(getClient(TEST_CLIENT_ID_ONE,
								List.of(new SupportedCredential("TypeA", FormatVO.LDP_VC)))),
						new ExpectedResult<>(getMetaData(List.of(new SupportedCredential("TypeA", FormatVO.LDP_VC))),
								"Proper issuer metadata should have been returned.")),
				Arguments.of(List.of(getClient(TEST_CLIENT_ID_ONE,
								List.of(new SupportedCredential("TypeA", FormatVO.LDP_VC),
										new SupportedCredential("TypeA", FormatVO.JWT_VC_JSON_LD)))),
						new ExpectedResult<>(
								getMetaData(
										List.of(
												new SupportedCredential("TypeA", FormatVO.LDP_VC),
												new SupportedCredential("TypeA", FormatVO.JWT_VC_JSON_LD))),
								"Proper issuer metadata with 2 credentials_supported should have been returned.")
				),
				Arguments.of(List.of(getClient(TEST_CLIENT_ID_ONE,
								List.of(new SupportedCredential("TypeA", FormatVO.LDP_VC),
										new SupportedCredential("TypeB", FormatVO.LDP_VC)))),
						new ExpectedResult<>(getMetaData(
								List.of(
										new SupportedCredential("TypeA", FormatVO.LDP_VC),
										new SupportedCredential("TypeB", FormatVO.LDP_VC))),
								"Proper issuer metadata with a combined credentials_supported should have been returned.")
				),
				Arguments.of(List.of(getClient(TEST_CLIENT_ID_ONE,
								List.of(new SupportedCredential("TypeA", FormatVO.LDP_VC),
										new SupportedCredential("TypeA", FormatVO.JWT_VC_JSON_LD),
										new SupportedCredential("TypeB", FormatVO.LDP_VC)))),
						new ExpectedResult<>(
								getMetaData(
										List.of(new SupportedCredential("TypeA", FormatVO.JWT_VC_JSON_LD),
												new SupportedCredential("TypeB", FormatVO.LDP_VC),
												new SupportedCredential("TypeA", FormatVO.LDP_VC))
								),
								"Proper issuer metadata with a combined credentials_supported should have been returned.")
				)
		);
	}

	public static IssuerMetaData getMetaData(List<SupportedCredential> supportedCredentials, String issuerDid)
			throws MalformedURLException {
		return IssuerMetaData.builder()
				.credentialEndpoint(
						new URL(String.format("http://localhost:8080/realms/test/verifiable-credential/%s/credential",
								issuerDid)))
				.credentialIssuer(new URL(String.format("http://localhost:8080/realms/test/verifiable-credential/%s",
						issuerDid)))
				.credentialsSupported(supportedCredentials.stream()
						.map(sc -> new SupportedCredentialMetadata(sc.getFormat().toString(),
								String.format("%s_%s", sc.getType(), sc.getFormat().toString()),
								Set.of(sc.getType())))
						.collect(Collectors.toSet())
				)
				.build();
	}

	public static IssuerMetaData getMetaData(List<SupportedCredential> supportedCredentials)
			throws MalformedURLException {
		return getMetaData(supportedCredentials, KEYCLOAK_ISSUER_DID);
	}

	private static Client getClient(String id, List<SupportedCredential> supportedTypes) {

		return Client.builder().id(id)
				.supportedTypes(supportedTypes).build();
	}

	@DisplayName("Issue credentials using a bearer token.")
	@ParameterizedTest
	@MethodSource("provideUsersAndClients")
	public void testVCIssuanceWithBearer(List<Client> clients, List<User> users, String userToRequest,
			String credentialToRequest,
			ExpectedResult<Set<Role>> expectedResult) throws Exception {
		testVCIssuance(true, () -> getUserTokenForAccounts(userToRequest), clients, users, userToRequest,
				credentialToRequest,
				expectedResult);
	}

	@DisplayName("Issue credentials using a token-parameter.")
	@ParameterizedTest
	@MethodSource("provideUsersAndClients")
	public void testVCIssuanceWithTokenParam(List<Client> clients, List<User> users, String userToRequest,
			String credentialToRequest,
			ExpectedResult<Set<Role>> expectedResult) throws Exception {

		testVCIssuance(false, () -> getUserTokenForAccounts(userToRequest), clients, users, userToRequest,
				credentialToRequest, expectedResult);
	}

	@DisplayName("Credentials issuance with an invalid token in the header should be denied")
	@ParameterizedTest
	@MethodSource("provideUsersAndClients")
	public void testVCIssuanceWithInvalidAuthHeader(List<Client> clients, List<User> users, String userToRequest,
			String credentialToRequest) throws Exception {

		ExpectedResult expectedResult = new ExpectedResult(null,
				"Without a valid token, nothing should be returned.",
				new ExpectedResult.Response(400, false));

		testVCIssuance(true, () -> "invalid", clients, users, userToRequest,
				credentialToRequest, expectedResult);
	}

	@DisplayName("Credentials issuance with an invalid token in the token parameter should be denied")
	@ParameterizedTest
	@MethodSource("provideUsersAndClients")
	public void testVCIssuanceWithInvalidToken(List<Client> clients, List<User> users, String userToRequest,
			String credentialToRequest) throws Exception {

		ExpectedResult expectedResult = new ExpectedResult(null,
				"Without a valid token, nothing should be returned.",
				new ExpectedResult.Response(400, false));

		testVCIssuance(false, () -> "invalid", clients, users, userToRequest,
				credentialToRequest, expectedResult);
	}

	@Test
	public void testIssuanceFlow() throws IOException, InterruptedException {
		String credentialType = "BatteryPassAuthCredential";

		Client clientOne = Client.builder()
				.id(TEST_CLIENT_ID_ONE)
				.roles(List.of(TEST_CREATOR_ROLE, TEST_CONSUMER_ROLE))
				.supportedTypes(List.of(new SupportedCredential(credentialType, FormatVO.LDP_VC),
						new SupportedCredential(credentialType, FormatVO.JWT_VC_JSON)))
				.build();
		assertClientCreation(clientOne.getId(), clientOne.getSupportedTypes());
		clientOne.getRoles().forEach(r -> createTestRole(clientOne.getId(), r));

		User testUser = User.builder().username("test-user")
				.firstName(Optional.of("Test"))
				.lastName(Optional.of("User"))
				.email(Optional.of("e@mail.org"))
				.clients(
						List.of(Client.builder()
								.id(TEST_CLIENT_ID_ONE)
								.roles(List.of(TEST_CONSUMER_ROLE))
								.build()))
				.build();
		createTestUser(testUser.getUsername(),
				testUser.getEmail(),
				testUser.getFirstName(),
				testUser.getLastName());

		testUser.clients.forEach(
				c -> addClientRoles(testUser.getUsername(), getClientRolesMap(c.getId(), c.getRoles())));
		String userToken = getUserTokenForAccounts(testUser.getUsername());

		// get credentials offer URI
		HttpResponse<String> response = HttpClient.newHttpClient()
				.send(HttpRequest.newBuilder()
								.GET()
								.uri(URI.create(
										String.format(
												"%s/realms/%s/verifiable-credential/%s/credential-offer-uri?type=%s&format=%s",
												KEYCLOAK_ADDRESS,
												TEST_REALM, KEYCLOAK_ISSUER_DID, credentialType, FormatVO.LDP_VC)))
								.header("Authorization", String.format("Bearer %s", userToken)).build(),
						HttpResponse.BodyHandlers.ofString());
		assertEquals(HttpStatus.SC_OK, response.statusCode(), "The offer URI should have been successfully returned.");

		CredentialOfferURI credentialOfferURI = OBJECT_MAPPER.readValue(response.body(), CredentialOfferURI.class);
		assertNotNull(credentialOfferURI.getIssuer(), "An issuer should be provided as part of the offer URI.");
		assertNotNull(credentialOfferURI.getNonce(), "A nonce should be provided as part of the offer URI.");

		// get credentials offer
		response = HttpClient.newHttpClient()
				.send(HttpRequest.newBuilder()
								.GET()
								.uri(URI.create(
										String.format("%s/credential-offer/%s",
												credentialOfferURI.getIssuer(), credentialOfferURI.getNonce())))
								.build(),
						HttpResponse.BodyHandlers.ofString());

		assertEquals(HttpStatus.SC_OK, response.statusCode(), "The offer should have been successfully returned.");
		CredentialsOfferVO credentialsOfferVO = OBJECT_MAPPER.readValue(response.body(), CredentialsOfferVO.class);
		assertNotNull(credentialsOfferVO.getCredentialIssuer(), "An issuer should provided as part of the offer.");
		String issuerUrl = credentialsOfferVO.getCredentialIssuer();

		List<CredentialObject> offeredCredentials = credentialsOfferVO.getCredentials().stream()
				.map(co -> OBJECT_MAPPER.convertValue(co, CredentialObject.class)).collect(
						Collectors.toList());
		assertEquals(1, offeredCredentials.size(), "Just the requested credential should be offered.");
		assertEquals(new CredentialObject(credentialType, FormatVO.LDP_VC), offeredCredentials.get(0),
				"Just the requested credential should be offered.");
		assertNotNull(credentialsOfferVO.getGrants(), "An authorization should be provided within the offer.");

		// get OIDC4VCI-compliant issuer meta-data
		HttpResponse<String> oid4VciResponse = HttpClient.newHttpClient()
				.send(HttpRequest.newBuilder()
								.GET()
								.uri(URI.create(
										issuerUrl + "/.well-known/openid-credential-issuer"))
								.build(),
						HttpResponse.BodyHandlers.ofString());
		assertEquals(HttpStatus.SC_OK, oid4VciResponse.statusCode(),
				"The metadata should have been successfully returned.");
		CredentialIssuerVO issuerVO = OBJECT_MAPPER.readValue(oid4VciResponse.body(), CredentialIssuerVO.class);
		assertEquals(credentialsOfferVO.getCredentialIssuer(), issuerVO.getCredentialIssuer(),
				"The metadata for the offered issuer should have been returend.");
		assertNotNull(issuerVO.getCredentialsSupported(), "The supported credentials should be included.");
		assertFalse(issuerVO.getCredentialsSupported().isEmpty(), "The supported credentials should be included.");
		boolean requestedCredentialIsSupported = issuerVO.getCredentialsSupported().stream().anyMatch(cs -> {
			FormatVO format = OBJECT_MAPPER.convertValue(cs.getFormat(), FormatVO.class);
			return (format == FormatVO.LDP_VC && cs.getTypes().contains(credentialType));
		});
		assertTrue(requestedCredentialIsSupported, "The requested credential should be supported by the issuer.");

		// follow authorization server address to get openid-configuration for the provided issuer
		HttpResponse<String> oidConfigResponse = HttpClient.newHttpClient()
				.send(HttpRequest.newBuilder()
								.GET()
								.uri(URI.create(
										issuerUrl + "/.well-known/openid-configuration"))
								.build(),
						HttpResponse.BodyHandlers.ofString());
		assertEquals(HttpStatus.SC_OK, oidConfigResponse.statusCode(),
				"The config should have been successfully returned.");
		Map<String, Object> configMap = OBJECT_MAPPER.readValue(oidConfigResponse.body(),
				new TypeReference<Map<String, Object>>() {
				});

		assertNotNull(configMap.get("token_endpoint"), "The token_endpoint should be provided in the metadata.");
		assertNotNull(configMap.get("credential_endpoint"),
				"The credential_endpoint should be provided in the metadata.");
		assertEquals(configMap.get("credential_endpoint"), issuerVO.getCredentialEndpoint(),
				"The credential endpoint should be present in both.");
		assertNotNull(configMap.get("grant_types_supported"),
				"Information about the supported grant_types should be included.");
		List<String> supportedGrantTypes = OBJECT_MAPPER.convertValue(configMap.get("grant_types_supported"),
				new TypeReference<List<String>>() {
				});
		assertTrue(supportedGrantTypes.contains(GRANT_TYPE_PRE_AUTHORIZED_CODE),
				"The preauthorized grant type should be supported.");

		Map<String, String> tokenRequestFormData = Map.of("grant_type",
				GRANT_TYPE_PRE_AUTHORIZED_CODE, "code", credentialsOfferVO.getGrants()
						.getUrnColonIetfColonParamsColonOauthColonGrantTypeColonPreAuthorizedCode()
						.getPreAuthorizedCode());

		// now get an access token
		HttpResponse<String> tokenResponse = HttpClient.newHttpClient()
				.send(HttpRequest.newBuilder()
								.POST(HttpRequest.BodyPublishers.ofString(getFormDataAsString(tokenRequestFormData)))
								.header("Content-Type", "application/x-www-form-urlencoded")
								.uri(URI.create(configMap.get("token_endpoint").toString()))
								.build(),
						HttpResponse.BodyHandlers.ofString());

		assertEquals(HttpStatus.SC_OK, tokenResponse.statusCode(), "The token should have been successfully provided.");
		TokenResponse token = OBJECT_MAPPER.readValue(tokenResponse.body(), TokenResponse.class);
		assertNotNull(token.getAccessToken(), "The access token should have been provided.");

		Map<String, Object> credentialRequest = Map.of("format", FormatVO.LDP_VC, "types", List.of(credentialType));

		// use the token to get the credential
		HttpResponse<String> credentialResponse = HttpClient.newHttpClient()
				.send(HttpRequest.newBuilder()
								.POST(HttpRequest.BodyPublishers.ofString(OBJECT_MAPPER.writeValueAsString(credentialRequest)))
								.uri(URI.create(issuerVO.getCredentialEndpoint()))
								.header("Authorization", String.format("Bearer %s", token.getAccessToken()))
								.header("Content-Type", "application/json")
								.build(),
						HttpResponse.BodyHandlers.ofString());
		assertEquals(HttpStatus.SC_OK, credentialResponse.statusCode(),
				"The credential should have been successfully created.");

		CredentialResponseVO credentialResponseVO = OBJECT_MAPPER.readValue(credentialResponse.body(),
				CredentialResponseVO.class);
		assertEquals(FormatVO.LDP_VC, credentialResponseVO.getFormat(),
				"The requested format should have been returned");
		assertNotNull(credentialResponseVO.getCredential(), "The credential should be returned.");

		Map<String, Object> credentialMap = OBJECT_MAPPER.convertValue(credentialResponseVO.getCredential(),
				new TypeReference<Map<String, Object>>() {
				});

		assertTrue(credentialMap.containsKey("type"), "The credential should have the types contained.");
		assertTrue(OBJECT_MAPPER.convertValue(credentialMap.get("type"), List.class).contains(credentialType),
				"The credential should have the correct type.");
		assertTrue(credentialMap.containsKey("proof"), "The credential should be proofen.");
		assertNotNull(credentialMap.get("credentialSubject"), "A subject should be set for the credential.");
		assertEquals(KEYCLOAK_ISSUER_DID, credentialMap.get("issuer"),
				"The issuer should be the one we asked for the credential.");
	}

	private void testVCIssuance(boolean useAuthHeader, Callable<String> tokenMethod, List<Client> clients,
			List<User> users,
			String userToRequest,
			String credentialToRequest,
			ExpectedResult<Set<Role>> expectedResult)
			throws Exception {
		clients.forEach(c -> {
			assertClientCreation(c.getId(), c.getSupportedTypes());
			c.getRoles().forEach(r -> createTestRole(c.getId(), r));
		});

		users.forEach(user -> {
			createTestUser(user.getUsername(), user.getEmail(), user.getFirstName(), user.getLastName());
			user.clients.forEach(c -> addClientRoles(user.getUsername(), getClientRolesMap(c.getId(), c.getRoles())));
		});

		HttpRequest.Builder requestBuilder = HttpRequest.newBuilder().GET();

		if (useAuthHeader) {
			requestBuilder
					.uri(URI.create(
							String.format("%s/realms/%s/verifiable-credential/%s?type=%s", KEYCLOAK_ADDRESS,
									TEST_REALM, KEYCLOAK_ISSUER_DID, credentialToRequest)))
					.header("Authorization", String.format("Bearer %s", tokenMethod.call()));
		} else {
			requestBuilder
					.uri(URI.create(
							String.format("%s/realms/%s/verifiable-credential/%s?type=%s&token=%s", KEYCLOAK_ADDRESS,
									TEST_REALM, KEYCLOAK_ISSUER_DID, credentialToRequest, tokenMethod.call())));
		}

		HttpResponse<String> response = HttpClient.newHttpClient()
				.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());

		assertEquals(expectedResult.getResponse().getCode(),
				response.statusCode(),
				expectedResult.getMessage());
		if (expectedResult.getResponse().isSuccess()) {
			VerifiableCredential receivedVC = OBJECT_MAPPER.readValue(response.body(), VerifiableCredential.class);
			CredentialSubject credentialSubject = receivedVC.getCredentialSubject();
			assertEquals(expectedResult.getExpectedResult(), credentialSubject.getRoles(),
					expectedResult.getMessage());

			User requestedUser = users.stream()
					.filter(u -> u.getUsername().equals(userToRequest))
					.findFirst()
					.get();

			requestedUser.getLastName().ifPresentOrElse(
					lastName -> assertEquals(lastName, credentialSubject.getFamilyName(), expectedResult.getMessage()),
					() -> assertNull(credentialSubject.getFamilyName(), expectedResult.getMessage()));
			requestedUser.getFirstName().ifPresentOrElse(
					firstName -> assertEquals(firstName, credentialSubject.getFirstName(), expectedResult.getMessage()),
					() -> assertNull(credentialSubject.getFirstName(), expectedResult.getMessage()));
			requestedUser.getEmail().ifPresentOrElse(
					email -> assertEquals(email, credentialSubject.getEmail(), expectedResult.getMessage()),
					() -> assertNull(credentialSubject.getEmail(), expectedResult.getMessage()));
			assertEquals(issuerDid, receivedVC.getIssuer(), expectedResult.getMessage());
			assertTrue(receivedVC.getType().contains(credentialToRequest), expectedResult.getMessage());
		} else {
			try {
				OBJECT_MAPPER.readValue(response.body(), VerifiableCredential.class);
				fail(expectedResult.getMessage());
			} catch (Exception e) {
				// we want this to fail.
			}
		}
	}

	public static Stream<Arguments> provideUsersAndClients() {
		return Stream.of(
				Arguments.of(List.of(Client.builder()
										.id(TEST_CLIENT_ID_ONE)
										.roles(List.of(TEST_CREATOR_ROLE, TEST_CONSUMER_ROLE))
										.supportedTypes(List.of(new SupportedCredential("BatteryPassAuthCredential", FormatVO.LDP_VC)))
										.build(),
								Client.builder()
										.id(TEST_CLIENT_ID_TWO)
										.roles(List.of(TEST_CONSUMER_ROLE))
										.supportedTypes(List.of(new SupportedCredential("SomethingElse", FormatVO.LDP_VC)))
										.build()),
						List.of(User.builder().username("test-user")
								.firstName(Optional.of("Test"))
								.lastName(Optional.of("User"))
								.email(Optional.of("e@mail.org"))
								.clients(
										List.of(Client.builder()
												.id(TEST_CLIENT_ID_ONE)
												.roles(List.of(TEST_CONSUMER_ROLE))
												.build()))
								.build()),
						"test-user",
						"BatteryPassAuthCredential",
						new ExpectedResult<>(
								Set.of(Role.builder().names(Set.of(TEST_CONSUMER_ROLE)).target(TEST_CLIENT_ID_ONE)
										.build()),
								"The credential should just contain the assigned role.",
								new ExpectedResult.Response(200, true))),
				Arguments.of(List.of(Client.builder()
								.id(TEST_CLIENT_ID_ONE)
								.roles(List.of(TEST_CREATOR_ROLE, TEST_CONSUMER_ROLE))
								.supportedTypes(List.of(new SupportedCredential("BatteryPassAuthCredential", FormatVO.LDP_VC)))
								.build()),
						List.of(User.builder().username("test-user")
								.lastName(Optional.of("User"))
								.email(Optional.of("e@mail.org"))
								.clients(
										List.of(Client.builder()
												.id(TEST_CLIENT_ID_ONE)
												.roles(List.of(TEST_CONSUMER_ROLE))
												.build()))
								.build()),
						"test-user",
						"BatteryPassAuthCredential",
						new ExpectedResult<>(
								Set.of(Role.builder().names(Set.of(TEST_CONSUMER_ROLE)).target(TEST_CLIENT_ID_ONE)
										.build()),
								"The credential should just contain the available values.",
								new ExpectedResult.Response(200, true))),
				Arguments.of(List.of(Client.builder()
								.id(TEST_CLIENT_ID_ONE)
								.roles(List.of(TEST_CREATOR_ROLE, TEST_CONSUMER_ROLE))
								.supportedTypes(List.of(new SupportedCredential("BatteryPassAuthCredential", FormatVO.LDP_VC)))
								.build()),
						List.of(User.builder().username("test-user")
								.lastName(Optional.of("User"))
								.clients(
										List.of(Client.builder()
												.id(TEST_CLIENT_ID_ONE)
												.roles(List.of(TEST_CONSUMER_ROLE))
												.build()))
								.build()),
						"test-user",
						"BatteryPassAuthCredential",
						new ExpectedResult<>(
								Set.of(Role.builder().names(Set.of(TEST_CONSUMER_ROLE)).target(TEST_CLIENT_ID_ONE)
										.build()),
								"The credential should just contain the available values.",
								new ExpectedResult.Response(200, true))), Arguments.of(List.of(Client.builder()
								.id(TEST_CLIENT_ID_ONE)
								.roles(List.of(TEST_CREATOR_ROLE, TEST_CONSUMER_ROLE))
								.supportedTypes(List.of(new SupportedCredential("BatteryPassAuthCredential", FormatVO.LDP_VC)))
								.build()),
						List.of(User.builder().username("test-user")
								.clients(
										List.of(Client.builder()
												.id(TEST_CLIENT_ID_ONE)
												.roles(List.of(TEST_CONSUMER_ROLE))
												.build()))
								.build()),
						"test-user",
						"BatteryPassAuthCredential",
						new ExpectedResult<>(
								Set.of(Role.builder().names(Set.of(TEST_CONSUMER_ROLE)).target(TEST_CLIENT_ID_ONE)
										.build()),
								"The credential should just contain the available values.",
								new ExpectedResult.Response(200, true))),
				Arguments.of(List.of(Client.builder()
								.id(TEST_CLIENT_ID_ONE)
								.roles(List.of(TEST_CREATOR_ROLE, TEST_CONSUMER_ROLE))
								.supportedTypes(List.of(new SupportedCredential("BatteryPassAuthCredential", FormatVO.LDP_VC)))
								.build()),
						List.of(User.builder().username("test-user")
								.firstName(Optional.of("Test"))
								.lastName(Optional.of("User"))
								.email(Optional.of("e@mail.org"))
								.clients(
										List.of(Client.builder()
												.id(TEST_CLIENT_ID_ONE)
												.roles(List.of(TEST_CONSUMER_ROLE, TEST_CREATOR_ROLE))
												.build()))
								.build()),
						"test-user",
						"BatteryPassAuthCredential",
						new ExpectedResult<>(
								Set.of(Role.builder().names(Set.of(TEST_CONSUMER_ROLE, TEST_CREATOR_ROLE))
										.target(TEST_CLIENT_ID_ONE)
										.build()),
								"The credential should just contain all assigned roles.",
								new ExpectedResult.Response(200, true))),
				Arguments.of(List.of(Client.builder()
								.id(TEST_CLIENT_ID_ONE)
								.roles(List.of(TEST_CREATOR_ROLE, TEST_CONSUMER_ROLE))
								.supportedTypes(List.of(new SupportedCredential("BatteryPassAuthCredential", FormatVO.LDP_VC)))
								.build()),
						List.of(User.builder().username("test-user")
								.firstName(Optional.of("Test"))
								.lastName(Optional.of("User"))
								.email(Optional.of("e@mail.org"))
								.clients(List.of())
								.build()),
						"test-user",
						"BatteryPassAuthCredential",
						new ExpectedResult<>(
								null,
								"If no role is assigned, an empty credentials should be returned",
								new ExpectedResult.Response(200, true))),
				Arguments.of(List.of(Client.builder()
										.id(TEST_CLIENT_ID_ONE)
										.roles(List.of(TEST_CREATOR_ROLE, TEST_CONSUMER_ROLE))
										.supportedTypes(List.of(new SupportedCredential("BatteryPassAuthCredential", FormatVO.LDP_VC)))
										.build(),
								Client.builder()
										.id(TEST_CLIENT_ID_TWO)
										.roles(List.of(TEST_CREATOR_ROLE))
										.supportedTypes(
												List.of(new SupportedCredential("BatteryPassAuthCredential", FormatVO.LDP_VC)))
										.build()),
						List.of(User.builder().username("test-user")
								.firstName(Optional.of("Test"))
								.lastName(Optional.of("User"))
								.email(Optional.of("e@mail.org"))
								.clients(
										List.of(Client.builder()
														.id(TEST_CLIENT_ID_ONE)
														.roles(List.of(TEST_CONSUMER_ROLE, TEST_CREATOR_ROLE))
														.build(),
												Client.builder()
														.id(TEST_CLIENT_ID_TWO)
														.roles(List.of(TEST_CREATOR_ROLE))
														.build()))
								.build()),
						"test-user",
						"BatteryPassAuthCredential",
						new ExpectedResult<>(
								Set.of(Role.builder().names(Set.of(TEST_CONSUMER_ROLE, TEST_CREATOR_ROLE))
												.target(TEST_CLIENT_ID_ONE)
												.build(),
										Role.builder().names(Set.of(TEST_CREATOR_ROLE)).target(TEST_CLIENT_ID_TWO)
												.build()),
								"The credential should just contain the assigned roles from all assigned clients.",
								new ExpectedResult.Response(200, true))),
				Arguments.of(List.of(Client.builder()
								.id(TEST_CLIENT_ID_ONE)
								.roles(List.of(TEST_CREATOR_ROLE, TEST_CONSUMER_ROLE))
								.supportedTypes(List.of(new SupportedCredential("BatteryPassAuthCredential", FormatVO.LDP_VC)))
								.build()
						),
						List.of(User.builder().username("test-user")
								.firstName(Optional.of("Test"))
								.lastName(Optional.of("User"))
								.email(Optional.of("e@mail.org"))
								.clients(
										List.of(Client.builder()
												.id(TEST_CLIENT_ID_ONE)
												.roles(List.of(TEST_CONSUMER_ROLE, TEST_CREATOR_ROLE))
												.build()))
								.build()),
						"test-user",
						"SomethingThatDoesNotExist",
						new ExpectedResult<>(
								Set.of(),
								"No credential should be issued, if something unsupported is requested.",
								new ExpectedResult.Response(400, false)))
		);
	}

	private void enableDirectAccessForAccountConsole() {
		ClientRepresentation accountConsole = getAdminKeycloak().realm(TEST_REALM).clients()
				.findByClientId(ACCOUNT_CONSOLE_CLIENT_ID).get(0);

		accountConsole.setDirectAccessGrantsEnabled(true);

		getAdminKeycloak().realm(TEST_REALM).clients().get(accountConsole.getId()).update(accountConsole);
	}

	private String getUserTokenForAccounts(String username) {

		TokenManager tokenManager = KeycloakBuilder.builder()
				.username(username)
				.password(USER_PASSWORD)
				.realm(TEST_REALM)
				.grantType("password")
				.clientId(ACCOUNT_CONSOLE_CLIENT_ID)
				.serverUrl(KEYCLOAK_ADDRESS)
				.build()
				.tokenManager();
		return tokenManager.getAccessToken().getToken();
	}

	private String getUserId(String username) {
		return getAdminKeycloak()
				.realm(TEST_REALM)
				.users()
				.list()
				.stream().filter(ur -> ur.getUsername().equals(username))
				.findFirst()
				.map(UserRepresentation::getId).orElseThrow(() -> new RuntimeException("no such user exists"));
	}

	private String getClientId(String client) {
		return getAdminKeycloak()
				.realm(TEST_REALM)
				.clients()
				.findAll()
				.stream()
				.filter(cr -> cr.getClientId().equals(client))
				.findFirst()
				.map(ClientRepresentation::getId)
				.orElseThrow(() -> new RuntimeException("no such client exists"));
	}

	private void addClientRoles(String user, Map<String, List<RoleRepresentation>> clientRoles) {
		clientRoles.forEach((key, value) -> {
			String userId = getUserId(user);
			getAdminKeycloak().realm(TEST_REALM)
					.users().get(userId).roles().clientLevel(key).add(value);
		});

	}

	private void createTestUser(String name) {

		createTestUser(name, Optional.empty(), Optional.empty(), Optional.empty());
	}

	private Map<String, List<RoleRepresentation>> getClientRolesMap(String clientId, List<String> roleNames) {
		List<ClientRepresentation> representations = getAdminKeycloak()
				.realm(TEST_REALM)
				.clients()
				.findByClientId(clientId);

		if (representations.isEmpty()) {
			throw new RuntimeException(String.format("No client %s exists.", clientId));
		}

		String id = representations.get(0).getId();

		List<RoleRepresentation> roleIds = getAdminKeycloak()
				.realm(TEST_REALM)
				.clients()
				.get(id)
				.roles().list().stream().filter(rr -> roleNames.contains(rr.getName()))
				.collect(
						Collectors.toList());
		return Map.of(id, roleIds);
	}

	private void createTestUser(String name, Optional<String> email,
			Optional<String> firstName, Optional<String> lastName) {

		CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
		credentialRepresentation.setType("Password");
		credentialRepresentation.setValue(USER_PASSWORD);

		UserRepresentation userRepresentation = new UserRepresentation();
		userRepresentation.setUsername(name);
		userRepresentation.setEnabled(true);
		userRepresentation.setCredentials(List.of(credentialRepresentation));
		email.ifPresent(userRepresentation::setEmail);
		firstName.ifPresent(userRepresentation::setFirstName);
		lastName.ifPresent(userRepresentation::setLastName);

		getAdminKeycloak()
				.realm(TEST_REALM)
				.users()
				.create(userRepresentation);

		addClientRoles(name, getClientRolesMap("account", List.of("manage-account")));
	}

	private void createTestRole(String clientId, String roleName) {
		String id = getClientId(clientId);
		RoleRepresentation roleRepresentation = new RoleRepresentation();
		roleRepresentation.setName(roleName);
		roleRepresentation.setId(roleName);

		roleRepresentation.setClientRole(true);

		getAdminKeycloak()
				.realm(TEST_REALM)
				.clients()
				.get(id)
				.roles().create(roleRepresentation);
	}

	private void createTestRealm() {
		RoleRepresentation defaultRole = new RoleRepresentation();
		defaultRole.setName("defaultRole");
		RealmRepresentation realmRepresentation = new RealmRepresentation();
		realmRepresentation.setId(TEST_REALM);
		realmRepresentation.setRealm(TEST_REALM);
		realmRepresentation.setEnabled(true);
		realmRepresentation.setDefaultRole(defaultRole);
		try {
			getAdminKeycloak()
					.realms().create(realmRepresentation);
		} catch (ClientErrorException e) {
			// incase an uncleaned environment is provided
			if (e.getResponse().getStatus() == 409) {
				deleteTestRealm();
				createTestRealm();
			}
		}
	}

	private void deleteTestRealm() {
		getAdminKeycloak()
				.realms()
				.realm(TEST_REALM).remove();
	}

	private void assertClientCreation(String clientId,
			List<SupportedCredential> supportedTypes) {
		ClientRepresentation clientRepresentation = new ClientRepresentation();
		clientRepresentation.setClientId(clientId);
		clientRepresentation.setName(clientId);
		clientRepresentation.setDescription("My test client.");
		clientRepresentation.setEnabled(true);
		clientRepresentation.setProtocol(SIOP2LoginProtocolFactory.PROTOCOL_ID);
		Map<String, String> attributes = new HashMap<>();

		supportedTypes.forEach(st -> {
			String typeKey = String.format("vctypes_%s", st.getType());
			if (attributes.containsKey(typeKey)) {
				attributes.put(typeKey, String.format("%s,%s", attributes.get(typeKey), st.getFormat().toString()));
			} else {
				attributes.put(typeKey, st.getFormat().toString());
			}
			attributes.put(String.format("%s_claims",st.getType()),"email,firstName,familyName,roles");
		});

		clientRepresentation.setAttributes(attributes);

		Response response = getAdminKeycloak()
				.realm(TEST_REALM)
				.clients()
				.create(clientRepresentation);

		assertEquals(201, response.getStatus(), "The client should have been successfully created.");
	}

	private Keycloak getAdminKeycloak() {
		return KeycloakBuilder.builder()
				.username(ADMIN_USERNAME)
				.password(ADMIN_PASSWORD)
				.realm(MASTER_REALM)
				.grantType("password")
				.clientId(ADMIN_CLI_CLIENT_ID)
				.serverUrl(KEYCLOAK_ADDRESS)
				.build();
	}

	private static String getFormDataAsString(Map<String, String> formData) {
		StringBuilder formBodyBuilder = new StringBuilder();
		for (Map.Entry<String, String> singleEntry : formData.entrySet()) {
			if (formBodyBuilder.length() > 0) {
				formBodyBuilder.append("&");
			}
			formBodyBuilder.append(URLEncoder.encode(singleEntry.getKey(), StandardCharsets.UTF_8));
			formBodyBuilder.append("=");
			formBodyBuilder.append(URLEncoder.encode(singleEntry.getValue(), StandardCharsets.UTF_8));
		}
		return formBodyBuilder.toString();
	}

	@Getter
	@Builder
	private static class Client {
		private String id;
		private List<String> roles;
		@Builder.Default
		private List<SupportedCredential> supportedTypes = List.of();
	}

	@Getter
	@Builder
	private static class User {
		private String username;
		@Builder.Default
		private Optional<String> email = Optional.empty();
		@Builder.Default
		private Optional<String> firstName = Optional.empty();
		@Builder.Default
		private Optional<String> lastName = Optional.empty();
		private List<Client> clients;
	}
}
