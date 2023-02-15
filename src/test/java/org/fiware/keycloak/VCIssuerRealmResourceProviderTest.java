package org.fiware.keycloak;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.fiware.keycloak.model.ErrorResponse;
import org.fiware.keycloak.model.ErrorType;
import org.fiware.keycloak.model.Role;
import org.fiware.keycloak.model.VCClaims;
import org.fiware.keycloak.model.VCConfig;
import org.fiware.keycloak.model.VCData;
import org.fiware.keycloak.model.VCRequest;
import org.fiware.keycloak.oidcvc.model.CredentialVO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientProvider;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.mockito.ArgumentCaptor;

import javax.ws.rs.core.Response;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.fiware.keycloak.VCIssuerRealmResourceProvider.LD_PROOF_TYPE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Slf4j
public class VCIssuerRealmResourceProviderTest {

	private static final String ISSUER_DID = "did:key:test";

	private final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
	private CredentialVO TEST_VC = new CredentialVO();

	private KeycloakSession keycloakSession;
	private AppAuthManager.BearerTokenAuthenticator bearerTokenAuthenticator;
	private WaltIdClient waltIdClient;

	private VCIssuerRealmResourceProvider testProvider;

	@BeforeEach
	public void setUp() throws NoSuchFieldException {
		this.keycloakSession = mock(KeycloakSession.class);
		this.bearerTokenAuthenticator = mock(AppAuthManager.BearerTokenAuthenticator.class);
		this.waltIdClient = mock(WaltIdClient.class);
		this.testProvider = new VCIssuerRealmResourceProvider(keycloakSession, ISSUER_DID, waltIdClient,
				bearerTokenAuthenticator, new ObjectMapper(), Clock.systemUTC());
	}

	@Test
	public void testGetTypesUnauthorized() {
		when(bearerTokenAuthenticator.authenticate()).thenReturn(null);

		try {
			testProvider.getTypes();
			fail("VCs should only be accessible for authorized users.");
		} catch (ErrorResponseException e) {
			assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), e.getResponse().getStatus(),
					"The response should be a 403.");
		}
	}

	@ParameterizedTest
	@MethodSource("provideTypesAndClients")
	public void testGetTypes(Stream<ClientModel> clientModelStream, ExpectedResult<List<String>> expectedResult) {
		AuthenticationManager.AuthResult authResult = mock(AuthenticationManager.AuthResult.class);
		UserModel userModel = mock(UserModel.class);
		KeycloakContext context = mock(KeycloakContext.class);
		RealmModel realmModel = mock(RealmModel.class);
		ClientProvider clientProvider = mock(ClientProvider.class);

		when(bearerTokenAuthenticator.authenticate()).thenReturn(authResult);
		when(authResult.getUser()).thenReturn(userModel);
		when(keycloakSession.getContext()).thenReturn(context);
		when(context.getRealm()).thenReturn(realmModel);
		when(keycloakSession.clients()).thenReturn(clientProvider);
		when(clientProvider.getClientsStream(any())).thenReturn(clientModelStream);

		List<String> returnedTypes = testProvider.getTypes();

		// copy to set to ignore order
		assertEquals(Set.copyOf(expectedResult.getExpectedResult()), Set.copyOf(returnedTypes),
				expectedResult.getMessage());
		// compare size in addition to the set, to not get duplicates
		assertEquals(expectedResult.getExpectedResult().size(), returnedTypes.size(), "The size should be equal.");
	}

	@Test
	public void testGetVCUnauthorized() {
		KeycloakContext context = mock(KeycloakContext.class);
		RealmModel realmModel = mock(RealmModel.class);
		when(keycloakSession.getContext()).thenReturn(context);
		when(context.getRealm()).thenReturn(realmModel);

		when(bearerTokenAuthenticator.authenticate()).thenReturn(null);

		try {
			testProvider.issueVerifiableCredential("MyVC", null);
			fail("VCs should only be accessible for authorized users.");
		} catch (ErrorResponseException e) {
			assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), e.getResponse().getStatus(),
					"The response should be a 400.");
			ErrorResponse er = OBJECT_MAPPER.convertValue(e.getResponse().getEntity(), ErrorResponse.class);
			assertEquals(ErrorType.INVALID_TOKEN.getValue(), er.getError(),
					"The response should have been denied because of the invalid token.");
		}
	}

	@Test
	public void testGetVCUnauthorizedToken() {
		KeycloakContext context = mock(KeycloakContext.class);
		RealmModel realmModel = mock(RealmModel.class);
		when(keycloakSession.getContext()).thenReturn(context);
		when(context.getRealm()).thenReturn(realmModel);

		when(bearerTokenAuthenticator.authenticate()).thenReturn(null);

		try {
			testProvider.issueVerifiableCredential("MyVC", "myToken");
			fail("VCs should only be accessible for authorized users.");
		} catch (ErrorResponseException e) {
			assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), e.getResponse().getStatus(),
					"The response should be a 400.");
			ErrorResponse er = OBJECT_MAPPER.convertValue(e.getResponse().getEntity(), ErrorResponse.class);
			assertEquals(ErrorType.INVALID_TOKEN.getValue(), er.getError(),
					"The response should have been denied because of the missing token.");
		}
	}

	@ParameterizedTest
	@MethodSource("provideTypesAndClients")
	public void testGetVCNoSuchType(Stream<ClientModel> clientModelStream, ExpectedResult<List<String>> ignored) {
		AuthenticationManager.AuthResult authResult = mock(AuthenticationManager.AuthResult.class);
		UserModel userModel = mock(UserModel.class);
		KeycloakContext context = mock(KeycloakContext.class);
		RealmModel realmModel = mock(RealmModel.class);
		ClientProvider clientProvider = mock(ClientProvider.class);

		when(bearerTokenAuthenticator.authenticate()).thenReturn(authResult);
		when(authResult.getUser()).thenReturn(userModel);
		when(keycloakSession.getContext()).thenReturn(context);
		when(context.getRealm()).thenReturn(realmModel);
		when(keycloakSession.clients()).thenReturn(clientProvider);
		when(clientProvider.getClientsStream(any())).thenReturn(clientModelStream);

		try {
			testProvider.issueVerifiableCredential("MyNonExistentType", null);
			fail("Not found types should be a 400");
		} catch (ErrorResponseException e) {
			assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), e.getResponse().getStatus(),
					"Not found types should be a 400");
			ErrorResponse er = OBJECT_MAPPER.convertValue(e.getResponse().getEntity(), ErrorResponse.class);
			assertEquals(ErrorType.UNSUPPORTED_CREDENTIAL_TYPE.getValue(), er.getError(),
					"The response should have been denied because of the unsupported type.");
		}
	}

	@ParameterizedTest
	@MethodSource("provideUserAndClients")
	public void testGetVC(UserModel userModel, Stream<ClientModel> clientModelStream,
			Map<ClientModel, Stream<RoleModel>> roleModelStreamMap,
			ExpectedResult<VCRequest> expectedResult) throws JsonProcessingException {
		AuthenticationManager.AuthResult authResult = mock(AuthenticationManager.AuthResult.class);
		KeycloakContext context = mock(KeycloakContext.class);
		RealmModel realmModel = mock(RealmModel.class);
		ClientProvider clientProvider = mock(ClientProvider.class);

		when(bearerTokenAuthenticator.authenticate()).thenReturn(authResult);
		when(authResult.getUser()).thenReturn(userModel);
		when(keycloakSession.getContext()).thenReturn(context);
		when(context.getRealm()).thenReturn(realmModel);
		when(keycloakSession.clients()).thenReturn(clientProvider);
		when(clientProvider.getClientsStream(any())).thenReturn(clientModelStream);

		when(userModel.getClientRoleMappingsStream(any())).thenAnswer(i -> roleModelStreamMap.get(i.getArguments()[0]));

		ArgumentCaptor<VCRequest> argument = ArgumentCaptor.forClass(VCRequest.class);

		when(waltIdClient.getVCFromWaltId(argument.capture())).thenReturn(OBJECT_MAPPER.writeValueAsString(TEST_VC));
		assertEquals(TEST_VC, testProvider.issueVerifiableCredential("MyType", null).getEntity(),
				"The requested VC should be returned.");

		assertEquals(expectedResult.getExpectedResult(), argument.getValue(), expectedResult.getMessage());
	}

	private static Arguments getArguments(UserModel um, Map<ClientModel, List<RoleModel>> clients,
			ExpectedResult expectedResult) {
		return Arguments.of(um,
				clients.keySet().stream(),
				clients.entrySet()
						.stream()
						.filter(e -> e.getValue() != null)
						.collect(
								Collectors.toMap(Map.Entry::getKey, e -> ((List) e.getValue()).stream(),
										(e1, e2) -> e1)),
				expectedResult);
	}

	private static Stream<Arguments> provideUserAndClients() {
		return Stream.of(
				getArguments(getUserModel("e@mail.org", "Happy", "User"),
						Map.of(getSiopClient("did:key:1",
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "MyType"),
										List.of("MyRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult(
								getVCRequest(Set.of(new Role(Set.of("MyRole"), "did:key:1")), "e@mail.org", "Happy",
										"User",
										null), "A valid VCRequest should have been sent to Walt-ID")
				),
				getArguments(getUserModel("e@mail.org", null, "User"),
						Map.of(getSiopClient("did:key:1",
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "MyType"),
										List.of("MyRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult(
								getVCRequest(Set.of(new Role(Set.of("MyRole"), "did:key:1")), "e@mail.org",
										null,
										"User",
										null), "A valid VCRequest should have been sent to Walt-ID")
				),
				getArguments(
						getUserModel("e@mail.org", null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "MyType"),
										List.of("MyRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult(
								getVCRequest(Set.of(new Role(Set.of("MyRole"), "did:key:1")), "e@mail.org",
										null,
										null,
										null), "A valid VCRequest should have been sent to Walt-ID")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "MyType"),
										List.of("MyRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult(
								getVCRequest(Set.of(new Role(Set.of("MyRole"), "did:key:1")), null, null,
										null,
										null), "A valid VCRequest should have been sent to Walt-ID")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "MyType"),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole"))),
						new ExpectedResult(
								getVCRequest(Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1")),
										null,
										null,
										null,
										null), "Multiple roles should be included")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "MyType"),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult(
								getVCRequest(Set.of(new Role(Set.of("MyRole"), "did:key:1")),
										null,
										null,
										null,
										null), "Only assigned roles should be included.")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "MyType"),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
								getSiopClient("did:key:2",
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "MyType"),
										List.of("AnotherRole")),
								List.of(getRoleModel("AnotherRole"))),
						new ExpectedResult(
								getVCRequest(Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"),
												new Role(Set.of("AnotherRole"), "did:key:2")), null,
										null,
										null,
										null), "The request should contain roles from both clients")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "MyType"),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
								getSiopClient("did:key:2",
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES,
												"AnotherType"),
										List.of("AnotherRole")),
								List.of(getRoleModel("AnotherRole"))),
						new ExpectedResult(
								getVCRequest(Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1")),
										null,
										null,
										null,
										null), "Only roles for supported clients should be included.")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "MyType",
												"vc_additional",
												"claim"),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
								getSiopClient("did:key:2",
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "MyType",
												"vc_more",
												"claims"),
										List.of("AnotherRole")),
								List.of(getRoleModel("AnotherRole"))),
						new ExpectedResult(
								getVCRequest(Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"),
												new Role(Set.of("AnotherRole"), "did:key:2")), null,
										null,
										null,
										Map.of("additional", "claim", "more", "claims")),
								"Additional claims should be included.")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "MyType",
												"vc_additional",
												"claim"),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
								getSiopClient("did:key:2",
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "MyType",
												"vc_additional",
												"claim"),
										List.of("AnotherRole")),
								List.of(getRoleModel("AnotherRole"))),
						new ExpectedResult(
								getVCRequest(Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"),
												new Role(Set.of("AnotherRole"), "did:key:2")), null,
										null,
										null,
										Map.of("additional", "claim")),
								"Additional claims should be included.")
				)
		);
	}

	private static VCRequest getVCRequest(Set<Role> roles, String email, String firstName, String lastName,
			Map<String, String> additionalClaims) {
		return VCRequest.builder()
				.templateId("MyType")
				.config(VCConfig.builder()
						.issuerDid(ISSUER_DID)
						.proofType(LD_PROOF_TYPE)
						.build())
				.credentialData(VCData.builder()
						.credentialSubject(
								VCClaims.builder()
										.roles(roles)
										.email(email)
										.firstName(firstName)
										.familyName(lastName)
										.additionalClaims(additionalClaims)
										.build()
						).build())
				.build();
	}

	private static Stream<Arguments> provideTypesAndClients() {
		return Stream.of(
				Arguments.of(Stream.of(getOidcClient(), getNullClient(), getSiopClient(
								Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "TestType"))),
						new ExpectedResult(List.of("TestType"), "The list of configured types should be returned.")),
				Arguments.of(Stream.of(getOidcClient(), getNullClient()),
						new ExpectedResult(List.of(), "An empty list should be returned if nothing is configured.")),
				Arguments.of(Stream.of(),
						new ExpectedResult(List.of(), "An empty list should be returned if nothing is configured.")),
				Arguments.of(
						Stream.of(getSiopClient(Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "TestType",
								"another", "attribute"))),
						new ExpectedResult(List.of("TestType"), "The list of configured types should be returned.")),
				Arguments.of(Stream.of(getSiopClient(
								Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "TestTypeA,TestTypeB"))),
						new ExpectedResult(List.of("TestTypeA", "TestTypeB"),
								"The list of configured types should be returned.")),
				Arguments.of(Stream.of(
								getSiopClient(Map.of()),
								getSiopClient(
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "TestTypeA,TestTypeB"))),
						new ExpectedResult(List.of("TestTypeA", "TestTypeB"),
								"The list of configured types should be returned.")),
				Arguments.of(Stream.of(
								getSiopClient(null),
								getSiopClient(
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "TestTypeA,TestTypeB"))),
						new ExpectedResult(List.of("TestTypeA", "TestTypeB"),
								"The list of configured types should be returned.")),
				Arguments.of(Stream.of(
								getSiopClient(Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "AnotherType")),
								getSiopClient(
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "TestTypeA,TestTypeB"))),
						new ExpectedResult(List.of("TestTypeA", "TestTypeB", "AnotherType"),
								"The list of configured types should be returned.")),
				Arguments.of(Stream.of(
								getSiopClient(
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "AnotherType,AndAnother")),
								getSiopClient(
										Map.of(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES, "TestTypeA,TestTypeB"))),
						new ExpectedResult(List.of("TestTypeA", "TestTypeB", "AnotherType", "AndAnother"),
								"The list of configured types should be returned."))
		);
	}

	private static UserModel getUserModel(String email, String firstName, String lastName) {
		UserModel userModel = mock(UserModel.class);
		when(userModel.getEmail()).thenReturn(email);
		when(userModel.getFirstName()).thenReturn(firstName);
		when(userModel.getLastName()).thenReturn(lastName);
		return userModel;
	}

	private static RoleModel getRoleModel(String name) {
		RoleModel roleModel = mock(RoleModel.class);
		when(roleModel.getName()).thenReturn(name);
		return roleModel;
	}

	private static ClientModel getOidcClient() {
		ClientModel clientA = mock(ClientModel.class);
		when(clientA.getProtocol()).thenReturn("OIDC");
		return clientA;
	}

	private static ClientModel getNullClient() {
		ClientModel clientA = mock(ClientModel.class);
		when(clientA.getProtocol()).thenReturn(null);
		return clientA;
	}

	private static ClientModel getSiopClient(String clientId, Map<String, String> attributes, List<String> roles) {
		Stream<RoleModel> roleModelStream = roles.stream().map(role -> {
			RoleModel roleModel = mock(RoleModel.class);
			when(roleModel.getName()).thenReturn(role);
			return roleModel;
		});
		ClientModel clientA = mock(ClientModel.class);
		when(clientA.getProtocol()).thenReturn(SIOP2LoginProtocolFactory.PROTOCOL_ID);
		when(clientA.getAttributes()).thenReturn(attributes);
		when(clientA.getClientId()).thenReturn(clientId);
		when(clientA.getRolesStream()).thenReturn(roleModelStream);
		return clientA;
	}

	private static ClientModel getSiopClient(Map<String, String> attributes) {
		return getSiopClient(null, attributes, List.of());
	}
}