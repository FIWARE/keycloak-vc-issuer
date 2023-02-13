package org.fiware.keycloak.it;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.awaitility.Awaitility;
import org.fiware.keycloak.ExpectedResult;
import org.fiware.keycloak.SIOP2LoginProtocolFactory;
import org.fiware.keycloak.model.CredentialSubject;
import org.fiware.keycloak.it.model.Role;
import org.fiware.keycloak.model.VerifiableCredential;
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
import javax.ws.rs.core.Response;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Slf4j
public class SIOP2IntegrationTest {

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	private static final String KEYCLOAK_ADDRESS = "http://localhost:8080";
	private static final String WALT_ID_CORE_ADDRESS = "http://localhost:7000";

	private static final String TEST_CLIENT_ID_ONE = "did:key:z6Mkv4Lh9zBTPLoFhLHHMFJA7YAeVw5HFYZV8rkdfY9fNtm3";
	private static final String TEST_CLIENT_ID_TWO = "did:key:z6Mkp7DVYuruxmKxsy2Rb3kMnfHgZZpbWYnY9rodvVfky7uj";

	private static final String KEYCLOAK_ISSUER_DID ="did:key:z6MkqmaCT2JqdUtLeKah7tEVfNXtDXtQyj4yxEgV11Y5CqUa";

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

	@ParameterizedTest
	@MethodSource("provideUsersAndClients")
	public void testVCIssuanceWithInvalidAuthHeader(List<Client> clients, List<User> users, String userToRequest,
			String credentialToRequest) throws Exception {

		ExpectedResult expectedResult = new ExpectedResult(null,
				"Without a valid token, nothing should be returned.",
				new ExpectedResult.Response(401, false));

		testVCIssuance(true, () -> "invalid", clients, users, userToRequest,
				credentialToRequest, expectedResult);
	}

	@ParameterizedTest
	@MethodSource("provideUsersAndClients")
	public void testVCIssuanceWithInvalidToken(List<Client> clients, List<User> users, String userToRequest,
			String credentialToRequest) throws Exception {

		ExpectedResult expectedResult = new ExpectedResult(null,
				"Without a valid token, nothing should be returned.",
				new ExpectedResult.Response(401, false));

		testVCIssuance(false, () -> "invalid", clients, users, userToRequest,
				credentialToRequest, expectedResult);
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
							String.format("%s/realms/%s/verifiable-credential?type=%s", KEYCLOAK_ADDRESS,
									TEST_REALM, credentialToRequest)))
					.header("Authorization", String.format("Bearer %s", tokenMethod.call()));
		} else {
			requestBuilder
					.uri(URI.create(
							String.format("%s/realms/%s/verifiable-credential?type=%s&token=%s", KEYCLOAK_ADDRESS,
									TEST_REALM, credentialToRequest, tokenMethod.call())));
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
										.supportedTypes(Optional.of("BatteryPassAuthCredential"))
										.build(),
								Client.builder()
										.id(TEST_CLIENT_ID_TWO)
										.roles(List.of(TEST_CONSUMER_ROLE))
										.supportedTypes(Optional.of("SomethingElse"))
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
								.supportedTypes(Optional.of("BatteryPassAuthCredential"))
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
								.supportedTypes(Optional.of("BatteryPassAuthCredential"))
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
								.supportedTypes(Optional.of("BatteryPassAuthCredential"))
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
								.supportedTypes(Optional.of("BatteryPassAuthCredential"))
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
								.supportedTypes(Optional.of("BatteryPassAuthCredential"))
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
										.supportedTypes(Optional.of("BatteryPassAuthCredential"))
										.build(),
								Client.builder()
										.id(TEST_CLIENT_ID_TWO)
										.roles(List.of(TEST_CREATOR_ROLE))
										.supportedTypes(Optional.of("BatteryPassAuthCredential"))
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
								.supportedTypes(Optional.of("BatteryPassAuthCredential"))
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
								new ExpectedResult.Response(404, false))));
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
			Optional<String> supportedTypes) {
		ClientRepresentation clientRepresentation = new ClientRepresentation();
		clientRepresentation.setClientId(clientId);
		clientRepresentation.setName(clientId);
		clientRepresentation.setDescription("My test client.");
		clientRepresentation.setEnabled(true);
		clientRepresentation.setProtocol(SIOP2LoginProtocolFactory.PROTOCOL_ID);
		Map<String, String> attributes = new HashMap<>();
		supportedTypes.ifPresent(st -> attributes.put("supportedVCTypes", st));

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

	@Getter
	@Builder
	private static class Client {
		private String id;
		private List<String> roles;
		@Builder.Default
		private Optional<String> supportedTypes = Optional.empty();
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
