package org.fiware.keycloak;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.fiware.keycloak.it.SIOP2IntegrationTest;
import org.fiware.keycloak.it.model.IssuerMetaData;
import org.fiware.keycloak.model.ErrorResponse;
import org.fiware.keycloak.model.ErrorType;
import org.fiware.keycloak.model.Role;
import org.fiware.keycloak.model.SupportedCredential;
import org.fiware.keycloak.model.VCClaims;
import org.fiware.keycloak.model.VCConfig;
import org.fiware.keycloak.model.VCData;
import org.fiware.keycloak.model.VCRequest;
import org.fiware.keycloak.oidcvc.model.CredentialVO;
import org.fiware.keycloak.oidcvc.model.FormatVO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientProvider;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.mockito.ArgumentCaptor;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
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
			testProvider.getTypes(ISSUER_DID);
			fail("VCs should only be accessible for authorized users.");
		} catch (WebApplicationException e) {
			assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), e.getResponse().getStatus(),
					"The response should be a 403.");
		}
	}

	@ParameterizedTest
	@MethodSource("provideTypesAndClients")
	public void testGetTypes(Stream<ClientModel> clientModelStream,
			ExpectedResult<Set<SupportedCredential>> expectedResult) {
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

		List<SupportedCredential> returnedTypes = testProvider.getTypes(ISSUER_DID);

		// copy to set to ignore order
		assertEquals(expectedResult.getExpectedResult(), Set.copyOf(returnedTypes),
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
			testProvider.issueVerifiableCredential(ISSUER_DID, "MyVC", null);
			fail("VCs should only be accessible for authorized users.");
		} catch (WebApplicationException e) {
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
			testProvider.issueVerifiableCredential(ISSUER_DID, "MyVC", "myToken");
			fail("VCs should only be accessible for authorized users.");
		} catch (WebApplicationException e) {
			assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), e.getResponse().getStatus(),
					"The response should be a 400.");
			ErrorResponse er = OBJECT_MAPPER.convertValue(e.getResponse().getEntity(), ErrorResponse.class);
			assertEquals(ErrorType.INVALID_TOKEN.getValue(), er.getError(),
					"The response should have been denied because of the missing token.");
		}
	}

	@ParameterizedTest
	@MethodSource("provideTypesAndClients")
	public void testGetVCNoSuchType(Stream<ClientModel> clientModelStream,
			ExpectedResult<Set<SupportedCredential>> ignored) {
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
			testProvider.issueVerifiableCredential(ISSUER_DID, "MyNonExistentType", null);
			fail("Not found types should be a 400");
		} catch (WebApplicationException e) {
			assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), e.getResponse().getStatus(),
					"Not found types should be a 400");
			ErrorResponse er = OBJECT_MAPPER.convertValue(e.getResponse().getEntity(), ErrorResponse.class);
			assertEquals(ErrorType.UNSUPPORTED_CREDENTIAL_TYPE.getValue(), er.getError(),
					"The response should have been denied because of the unsupported type.");
		}
	}

	@ParameterizedTest
	@MethodSource("provideClients")
	public void testGetIssuerData(Stream<ClientModel> clientModelStream, ExpectedResult<IssuerMetaData> expectedResult)
			throws URISyntaxException {
		KeycloakContext context = mock(KeycloakContext.class);
		RealmModel realmModel = mock(RealmModel.class);
		when(realmModel.getName()).thenReturn("test");
		when(realmModel.getClientsStream()).thenReturn(clientModelStream);
		KeycloakUriInfo keycloakUriInfo = mock(KeycloakUriInfo.class);
		when(keycloakUriInfo.getBaseUri()).thenReturn(new URI("http://localhost:8080"));
		when(context.getUri(any())).thenReturn(keycloakUriInfo);
		when(keycloakSession.getContext()).thenReturn(context);
		when(context.getRealm()).thenReturn(realmModel);

		Response metaDataResponse = testProvider.getIssuerMetadata(ISSUER_DID);
		assertEquals(HttpStatus.SC_OK, metaDataResponse.getStatus(), expectedResult.getMessage());
		assertEquals(expectedResult.getExpectedResult(),
				OBJECT_MAPPER.convertValue(metaDataResponse.getEntity(), IssuerMetaData.class),
				expectedResult.getMessage());
	}

	public static Stream<Arguments> provideClients() throws MalformedURLException {
		return Stream.of(
				Arguments.of(
						Stream.of(
								getSiopClient("did:key:1", Map.of("vctypes_MyType", FormatVO.JWT_VC_JSON_LD.toString()),
										List.of())),
						new ExpectedResult<>(
								SIOP2IntegrationTest.getMetaData(
										List.of(new SupportedCredential("MyType", FormatVO.JWT_VC_JSON_LD)),
										ISSUER_DID),
								"Issuer data wioth the clients types should be returend.")
				),
				Arguments.of(
						Stream.of(
								getSiopClient("did:key:1", Map.of("vctypes_MyType",
												FormatVO.JWT_VC_JSON_LD.toString() + "," + FormatVO.LDP_VC),
										List.of())),
						new ExpectedResult<>(
								SIOP2IntegrationTest.getMetaData(
										List.of(new SupportedCredential("MyType", FormatVO.JWT_VC_JSON_LD),
												new SupportedCredential("MyType", FormatVO.LDP_VC)), ISSUER_DID),
								"Issuer data with the clients types and multiple formats should be returned.")
				),
				Arguments.of(
						Stream.of(
								getSiopClient("did:key:1", Map.of("vctypes_MyType", FormatVO.JWT_VC_JSON_LD.toString()),
										List.of()),
								getSiopClient("did:key:2",
										Map.of("vctypes_MyOtherType", FormatVO.JWT_VC_JSON_LD.toString()),
										List.of())),
						new ExpectedResult<>(
								SIOP2IntegrationTest.getMetaData(
										List.of(new SupportedCredential("MyType", FormatVO.JWT_VC_JSON_LD),
												new SupportedCredential("MyOtherType", FormatVO.JWT_VC_JSON_LD)),
										ISSUER_DID),
								"Issuer data with multiple clients types should be returned.")
				),
				Arguments.of(
						Stream.of(
								getSiopClient("did:key:1", Map.of("vctypes_MyType", FormatVO.JWT_VC_JSON_LD.toString()),
										List.of()),
								getSiopClient("did:key:2", Map.of("vctypes_MyType", FormatVO.LDP_VC.toString()),
										List.of())),
						new ExpectedResult<>(
								SIOP2IntegrationTest.getMetaData(
										List.of(new SupportedCredential("MyType", FormatVO.LDP_VC),
												new SupportedCredential("MyType", FormatVO.JWT_VC_JSON_LD)),
										ISSUER_DID),
								"Issuer data with multiple clients formats should be returned.")
				),
				Arguments.of(
						Stream.of(
								getSiopClient("did:key:1", Map.of("vctypes_MyType", FormatVO.JWT_VC_JSON_LD.toString(),
												"vctypes_MyOtherType", FormatVO.JWT_VC_JSON_LD.toString()),
										List.of())),
						new ExpectedResult<>(
								SIOP2IntegrationTest.getMetaData(
										List.of(new SupportedCredential("MyOtherType", FormatVO.JWT_VC_JSON_LD),
												new SupportedCredential("MyType", FormatVO.JWT_VC_JSON_LD)),
										ISSUER_DID),
								"Issuer data with multiple typses should be returned.")
				)
		);
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
		assertEquals(TEST_VC,
				OBJECT_MAPPER.readValue(
						(String) testProvider.issueVerifiableCredential(ISSUER_DID, "MyType", null).getEntity(),
						CredentialVO.class),
				"The requested VC should be returned.");
		// randomly generated
		expectedResult.getExpectedResult().getConfig().setSubjectDid(argument.getValue().getConfig().getSubjectDid());
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
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString(),
												"MyType_claims", "email,firstName,familyName,roles"),
										List.of("MyRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult<>(
								getVCRequest(Set.of(new Role(Set.of("MyRole"), "did:key:1")), "e@mail.org", "Happy",
										"User",
										Map.of()), "A valid VCRequest should have been sent to Walt-ID")
				),
				getArguments(getUserModel("e@mail.org", null, "User"),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString(),
												"MyType_claims", "email,firstName,familyName,roles"),
										List.of("MyRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult<>(
								getVCRequest(Set.of(new Role(Set.of("MyRole"), "did:key:1")), "e@mail.org",
										null,
										"User",
										Map.of()), "A valid VCRequest should have been sent to Walt-ID")
				),
				getArguments(
						getUserModel("e@mail.org", null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString(),
												"MyType_claims", "email,firstName,familyName,roles"),
										List.of("MyRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult<>(
								getVCRequest(Set.of(new Role(Set.of("MyRole"), "did:key:1")), "e@mail.org",
										null,
										null,
										Map.of()), "A valid VCRequest should have been sent to Walt-ID")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString(),
												"MyType_claims", "email,firstName,familyName,roles"),
										List.of("MyRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult<>(
								getVCRequest(Set.of(new Role(Set.of("MyRole"), "did:key:1")), null, null,
										null,
										Map.of()), "A valid VCRequest should have been sent to Walt-ID")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString(),
												"MyType_claims", "email,firstName,familyName,roles"),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole"))),
						new ExpectedResult<>(
								getVCRequest(Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1")),
										null,
										null,
										null,
										Map.of()), "Multiple roles should be included")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString(),
												"MyType_claims", "email,firstName,familyName,roles"),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult<>(
								getVCRequest(Set.of(new Role(Set.of("MyRole"), "did:key:1")),
										null,
										null,
										null,
										Map.of()), "Only assigned roles should be included.")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString(),
												"MyType_claims", "email,firstName,familyName,roles"),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
								getSiopClient("did:key:2",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString(),
												"MyType_claims", "email,firstName,familyName,roles"),
										List.of("AnotherRole")),
								List.of(getRoleModel("AnotherRole"))),
						new ExpectedResult<>(
								getVCRequest(Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"),
												new Role(Set.of("AnotherRole"), "did:key:2")),
										null,
										null,
										null,
										Map.of()), "The request should contain roles from both clients")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString(),
												"MyType_claims", "email,firstName,familyName,roles"),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
								getSiopClient("did:key:2",
										Map.of("vctypes_AnotherType", FormatVO.LDP_VC.toString(),
												"AnotherType_claims", "email,firstName,familyName,roles"),
										List.of("AnotherRole")),
								List.of(getRoleModel("AnotherRole"))),
						new ExpectedResult<>(
								getVCRequest(Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1")),
										null,
										null,
										null,
										Map.of()), "Only roles for supported clients should be included.")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString(),
												"vc_additional", "claim",
												"MyType_claims", "email,firstName,familyName,roles,additional,more"),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
								getSiopClient("did:key:2",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString(),
												"vc_more", "claims",
												"MyType_claims", "email,firstName,familyName,roles,additional,more"),
										List.of("AnotherRole")),
								List.of(getRoleModel("AnotherRole"))),
						new ExpectedResult<>(
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
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString(),
												"vc_additional", "claim",
												"MyType_claims", "email,firstName,familyName,roles,additional"),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
								getSiopClient("did:key:2",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString(),
												"vc_additional", "claim",
												"MyType_claims", "email,firstName,familyName,roles,additional"),
										List.of("AnotherRole")),
								List.of(getRoleModel("AnotherRole"))),
						new ExpectedResult<>(
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
								Map.of("vctypes_TestType", FormatVO.LDP_VC.toString()))),
						new ExpectedResult<>(Set.of(new SupportedCredential("TestType", FormatVO.LDP_VC)),
								"The list of configured types should be returned.")),
				Arguments.of(Stream.of(getOidcClient(), getNullClient()),
						new ExpectedResult<>(Set.of(), "An empty list should be returned if nothing is configured.")),
				Arguments.of(Stream.of(),
						new ExpectedResult<>(Set.of(), "An empty list should be returned if nothing is configured.")),
				Arguments.of(
						Stream.of(getSiopClient(Map.of("vctypes_TestType", FormatVO.LDP_VC.toString(),
								"another", "attribute"))),
						new ExpectedResult<>(Set.of(new SupportedCredential("TestType", FormatVO.LDP_VC)),
								"The list of configured types should be returned.")),
				Arguments.of(Stream.of(getSiopClient(
								Map.of("vctypes_TestTypeA", FormatVO.LDP_VC.toString(), "vctypes_TestTypeB",
										FormatVO.LDP_VC.toString()))),
						new ExpectedResult<>(
								Set.of(new SupportedCredential("TestTypeA", FormatVO.LDP_VC),
										new SupportedCredential("TestTypeB", FormatVO.LDP_VC)),
								"The list of configured types should be returned.")),
				Arguments.of(Stream.of(
								getSiopClient(Map.of()),
								getSiopClient(
										Map.of("vctypes_TestTypeA", FormatVO.LDP_VC.toString(), "vctypes_TestTypeB",
												FormatVO.LDP_VC.toString()))),
						new ExpectedResult<>(
								Set.of(new SupportedCredential("TestTypeA", FormatVO.LDP_VC),
										new SupportedCredential("TestTypeB", FormatVO.LDP_VC)),
								"The list of configured types should be returned.")),
				Arguments.of(Stream.of(
								getSiopClient(null),
								getSiopClient(
										Map.of("vctypes_TestTypeA", FormatVO.LDP_VC.toString(), "vctypes_TestTypeB",
												FormatVO.LDP_VC.toString()))),
						new ExpectedResult<>(
								Set.of(new SupportedCredential("TestTypeA", FormatVO.LDP_VC),
										new SupportedCredential("TestTypeB", FormatVO.LDP_VC)),
								"The list of configured types should be returned.")),
				Arguments.of(Stream.of(
								getSiopClient(Map.of("vctypes_AnotherType", FormatVO.LDP_VC.toString())),
								getSiopClient(
										Map.of("vctypes_TestTypeA", FormatVO.LDP_VC.toString(), "vctypes_TestTypeB",
												FormatVO.LDP_VC.toString()))),
						new ExpectedResult<>(
								Set.of(new SupportedCredential("TestTypeA", FormatVO.LDP_VC),
										new SupportedCredential("TestTypeB", FormatVO.LDP_VC),
										new SupportedCredential("AnotherType", FormatVO.LDP_VC)),
								"The list of configured types should be returned.")),
				Arguments.of(Stream.of(
								getSiopClient(
										Map.of("vctypes_AnotherType", FormatVO.LDP_VC.toString(), "vctypes_AndAnother",
												FormatVO.LDP_VC.toString())),
								getSiopClient(
										Map.of("vctypes_TestTypeA", FormatVO.LDP_VC.toString(), "vctypes_TestTypeB",
												FormatVO.LDP_VC.toString()))),
						new ExpectedResult<>(
								Set.of(new SupportedCredential("TestTypeA", FormatVO.LDP_VC),
										new SupportedCredential("TestTypeB", FormatVO.LDP_VC),
										new SupportedCredential("AnotherType", FormatVO.LDP_VC),
										new SupportedCredential("AndAnother", FormatVO.LDP_VC)),
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