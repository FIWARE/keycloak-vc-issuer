package org.fiware.keycloak;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.fiware.keycloak.it.SIOP2IntegrationTest;
import org.fiware.keycloak.it.model.IssuerMetaData;
import org.fiware.keycloak.it.model.Role;
import org.fiware.keycloak.mappers.SIOP2StaticClaimMapper;
import org.fiware.keycloak.mappers.SIOP2SubjectIdMapper;
import org.fiware.keycloak.mappers.SIOP2TargetRoleMapper;
import org.fiware.keycloak.mappers.SIOP2UserAttributeMapper;
import org.fiware.keycloak.model.ErrorResponse;
import org.fiware.keycloak.model.ErrorType;
import org.fiware.keycloak.model.SupportedCredential;
import org.fiware.keycloak.oidcvc.model.FormatVO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientProvider;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.mockito.stubbing.Answer;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Slf4j
public class VCIssuerRealmResourceProviderTest {

	private static final String ISSUER_DID = "did:key:test";

	private final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
			.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
			.configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true).build();

	private KeycloakSession keycloakSession;
	private AppAuthManager.BearerTokenAuthenticator bearerTokenAuthenticator;

	private VCIssuerRealmResourceProvider testProvider;

	private Clock fixedClock = Clock.fixed(Instant.parse("2022-11-10T17:11:09.00Z"),
			ZoneId.of("Europe/Paris"));

	@BeforeEach
	public void setUp() throws NoSuchFieldException {
		URL url = getClass().getClassLoader().getResource("key.tls");

		this.keycloakSession = mock(KeycloakSession.class);
		this.bearerTokenAuthenticator = mock(AppAuthManager.BearerTokenAuthenticator.class);
		this.testProvider = new VCIssuerRealmResourceProvider(keycloakSession, ISSUER_DID, url.getPath(),
				bearerTokenAuthenticator, new ObjectMapper(), fixedClock);
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
			testProvider.issueVerifiableCredential(ISSUER_DID, "MyNonExistentType", "myToken");
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
		when(realmModel.getId()).thenReturn("test");
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
	public void testGetCredential(UserModel userModel, Stream<ClientModel> clientModelStream,
			Map<ClientModel, Stream<RoleModel>> roleModelStreamMap,
			ExpectedResult<Map> expectedResult, FormatVO requestedFormat)
			throws JsonProcessingException, VerificationException {
		List<ClientModel> clientModels = clientModelStream.toList();

		AuthenticationManager.AuthResult authResult = mock(AuthenticationManager.AuthResult.class);
		KeycloakContext context = mock(KeycloakContext.class);
		RealmModel realmModel = mock(RealmModel.class);
		ClientProvider clientProvider = mock(ClientProvider.class);

		UserSessionModel userSessionModel = mock(UserSessionModel.class);
		when(userSessionModel.getRealm()).thenReturn(realmModel);
		when(userSessionModel.getUser()).thenReturn(userModel);
		clientModels.forEach(cm -> when(realmModel.getClientByClientId(eq(cm.getClientId()))).thenReturn(cm));
		when(realmModel.getClientsStream()).thenReturn(clientModels.stream());

		when(bearerTokenAuthenticator.authenticate()).thenReturn(authResult);

		when(authResult.getUser()).thenReturn(userModel);
		when(authResult.getSession()).thenReturn(userSessionModel);

		when(keycloakSession.getContext()).thenReturn(context);
		when(context.getRealm()).thenReturn(realmModel);

		when(keycloakSession.clients()).thenReturn(clientProvider);
		when(clientProvider.getClientsStream(any())).thenReturn(clientModels.stream());

		when(userModel.getClientRoleMappingsStream(any())).thenAnswer(i -> roleModelStreamMap.get(i.getArguments()[0]));

		Object credential = testProvider.getCredential("MyType", requestedFormat);
		switch (requestedFormat) {
			case LDP_VC -> {
				Map verifiableCredential = OBJECT_MAPPER.convertValue(credential, Map.class);
				verifyLDCredential(expectedResult, verifiableCredential);
			}
			case JWT_VC_JSON_LD, JWT_VC, JWT_VC_JSON -> verifyJWTCredential(expectedResult, (String) credential);
		}
	}

	private void verifyJWTCredential(ExpectedResult<Map> expectedResult, String actualResult)
			throws VerificationException, JsonProcessingException {
		TokenVerifier<JsonWebToken> verifier = TokenVerifier.create(actualResult, JsonWebToken.class);
		JsonWebToken theJWT = verifier.getToken();
		assertEquals(ISSUER_DID, theJWT.getIssuer(), "The issuer should be properly set.");
		assertNotNull(theJWT.getSubject(), "A subject should be set.");
		assertNotNull(theJWT.getId(), "The jwt should have an id.");

		Map theVC = (Map) theJWT.getOtherClaims().get("vc");
		assertNotNull(theVC, "The vc should be part of the jwt.");
		List credentialType = (List) theVC.get("type");
		assertEquals(2, credentialType.size(), "Both types should be included.");
		assertTrue(credentialType.contains("MyType") && credentialType.contains("VerifiableCredential"),
				"The correct types should be included.");

		Map retrievedSubject = (Map) theVC.get("credentialSubject");
		Map expectedCredentialSubject = new HashMap(expectedResult.getExpectedResult());

		verifySubject(expectedResult, expectedCredentialSubject, retrievedSubject);

	}

	@ParameterizedTest
	@MethodSource("provideUserAndClientsLDP")
	public void testGetVC(UserModel userModel, Stream<ClientModel> clientModelStream,
			Map<ClientModel, Stream<RoleModel>> roleModelStreamMap,
			ExpectedResult<Map> expectedResult) throws JsonProcessingException {
		List<ClientModel> clientModels = clientModelStream.toList();

		AuthenticationManager.AuthResult authResult = mock(AuthenticationManager.AuthResult.class);
		KeycloakContext context = mock(KeycloakContext.class);
		RealmModel realmModel = mock(RealmModel.class);
		ClientProvider clientProvider = mock(ClientProvider.class);
		UserSessionModel userSessionModel = mock(UserSessionModel.class);
		when(userSessionModel.getRealm()).thenReturn(realmModel);
		when(userSessionModel.getUser()).thenReturn(userModel);
		clientModels.forEach(cm -> when(realmModel.getClientByClientId(eq(cm.getClientId()))).thenReturn(cm));

		when(bearerTokenAuthenticator.authenticate()).thenReturn(authResult);
		when(authResult.getUser()).thenReturn(userModel);
		when(authResult.getSession()).thenReturn(userSessionModel);
		when(keycloakSession.getContext()).thenReturn(context);
		when(context.getRealm()).thenReturn(realmModel);
		when(keycloakSession.clients()).thenReturn(clientProvider);
		// use then to open a new stream on each invocation
		when(clientProvider.getClientsStream(any())).then(f -> clientModels.stream());

		when(userModel.getClientRoleMappingsStream(any())).thenAnswer(i -> roleModelStreamMap.get(i.getArguments()[0]));

		Map credentialVO = OBJECT_MAPPER.convertValue(
				testProvider.issueVerifiableCredential(ISSUER_DID, "MyType", "myToken").getEntity(),
				Map.class);

		verifyLDCredential(expectedResult, credentialVO);
	}

	private void verifyLDCredential(ExpectedResult<Map> expectedResult, Map credentialVO)
			throws JsonProcessingException {
		assertEquals("2022-11-10T17:11:09Z", credentialVO.get("issuanceDate"),
				"The issuance data should be correctly set.");
		assertNotNull(credentialVO.get("@context"), "The context should be set on an ld-credential.");
		assertNotNull(credentialVO.get("proof"), "The proof should be included.");
		assertNotNull(credentialVO.get("id"), "The credential should have an id.");
		List credentialType = (List) credentialVO.get("type");
		assertEquals(2, credentialType.size(), "Both types should be included.");
		assertTrue(credentialType.contains("MyType") && credentialType.contains("VerifiableCredential"),
				"The correct types should be included.");

		assertEquals(ISSUER_DID, credentialVO.get("issuer"), "The correct issuer should be set.");

		Map expectedCredentialSubject = new HashMap(expectedResult.getExpectedResult());
		Map retrievedSubject = (Map) credentialVO.get("credentialSubject");
		assertNotNull(retrievedSubject.get("id"), "The id should have been set.");
		// remove the id, since its randomly generated.
		retrievedSubject.remove("id");

		verifySubject(expectedResult, expectedCredentialSubject, retrievedSubject);
	}

	private void verifySubject(ExpectedResult<Map> expectedResult, Map expectedCredentialSubject, Map retrievedSubject)
			throws JsonProcessingException {
		verifyRoles(expectedResult.getMessage(), expectedCredentialSubject, retrievedSubject);
		// roles are checked, can be removed to not interfer with next checks.
		expectedCredentialSubject.remove("roles");
		retrievedSubject.remove("roles");

		String expectedJson = OBJECT_MAPPER.writeValueAsString(expectedCredentialSubject);
		String retrievedJson = OBJECT_MAPPER.writeValueAsString(retrievedSubject);
		// we compare the json, to prevent order issues.
		assertEquals(expectedJson, retrievedJson, expectedResult.getMessage());
	}

	private void verifyRoles(String message, Map expectedCredentialSubject, Map retrievedSubject) {
		Set<Role> retrievedRoles = OBJECT_MAPPER.convertValue(retrievedSubject.get("roles"),
				new TypeReference<Set<Role>>() {
				});
		Set<Role> expectedRoles = OBJECT_MAPPER.convertValue(expectedCredentialSubject.get("roles"),
				new TypeReference<Set<Role>>() {
				});
		assertEquals(expectedRoles, retrievedRoles, message);
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
		return Stream.concat(provideUserAndClientsLDP().map(a -> {
					var argObjects = new ArrayList<>(Arrays.asList(a.get()));
					argObjects.add(FormatVO.LDP_VC);
					return Arguments.of(argObjects.toArray());
				}),
				provideUserAndClientsJWT().map(a -> {
					var argObjects = new ArrayList<>(Arrays.asList(a.get()));
					argObjects.add(FormatVO.JWT_VC);
					return Arguments.of(argObjects.toArray());
				}));
	}

	private static Stream<Arguments> provideUserAndClientsJWT() {
		return Stream.of(
				getArguments(getUserModel("e@mail.org", "Happy", "User"),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.JWT_VC.toString()),
										List.of("MyRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult<>(
								Map.of("email", "e@mail.org", "familyName", "User", "firstName", "Happy", "roles",
										Set.of(new Role(Set.of("MyRole"), "did:key:1"))),
								"A valid Credential should have been returned.")
				),
				getArguments(getUserModel("e@mail.org", null, "User"),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.JWT_VC.toString()),
										List.of("MyRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult<>(
								Map.of("email", "e@mail.org", "familyName", "User", "roles",
										Set.of(new Role(Set.of("MyRole"), "did:key:1"))),
								"A valid Credential should have been returned.")
				),
				getArguments(
						getUserModel("e@mail.org", null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.JWT_VC.toString()),
										List.of("MyRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult<>(
								Map.of("email", "e@mail.org", "roles",
										Set.of(new Role(Set.of("MyRole"), "did:key:1"))),
								"A valid Credential should have been returned.")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.JWT_VC.toString()),
										List.of("MyRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult<>(
								Map.of("roles",
										Set.of(new Role(Set.of("MyRole"), "did:key:1"))),
								"A valid Credential should have been returned.")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.JWT_VC.toString()),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole"))),
						new ExpectedResult<>(
								Map.of("roles",
										Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"))),
								"Multiple roles should be included")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.JWT_VC.toString()),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult<>(
								Map.of("roles",
										Set.of(new Role(Set.of("MyRole"), "did:key:1"))),
								"Only assigned roles should be included.")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.JWT_VC.toString()),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
								getSiopClient("did:key:2",
										Map.of("vctypes_MyType", FormatVO.JWT_VC.toString()),
										List.of("AnotherRole")),
								List.of(getRoleModel("AnotherRole"))),
						new ExpectedResult<>(
								Map.of("roles",
										Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"),
												new Role(Set.of("AnotherRole"), "did:key:2"))),
								"The request should contain roles from both clients")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.JWT_VC.toString()),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
								getSiopClient("did:key:2",
										Map.of("vctypes_AnotherType", FormatVO.JWT_VC.toString()),
										List.of("AnotherRole")),
								List.of(getRoleModel("AnotherRole"))),
						new ExpectedResult<>(
								Map.of("roles",
										Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"))),
								"Only roles for supported clients should be included.")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.JWT_VC.toString()),
										List.of("MyRole", "MySecondRole"),
										Map.of("more", "claims")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
								getSiopClient("did:key:2",
										Map.of("vctypes_MyType", FormatVO.JWT_VC.toString()),
										List.of("AnotherRole"),
										Map.of("additional", "claim")),
								List.of(getRoleModel("AnotherRole"))),
						new ExpectedResult<>(
								Map.of("roles",
										Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"),
												new Role(Set.of("AnotherRole"), "did:key:2")),
										"additional", "claim", "more", "claims"),
								"Additional claims should be included.")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.JWT_VC.toString()),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
								getSiopClient("did:key:2",
										Map.of("vctypes_MyType", FormatVO.JWT_VC.toString()),
										List.of("AnotherRole"),
										Map.of("additional", "claim")),
								List.of(getRoleModel("AnotherRole"))),
						new ExpectedResult<>(
								Map.of("additional", "claim", "roles",
										Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"),
												new Role(Set.of("AnotherRole"), "did:key:2"))),
								"Additional claims should be included.")
				)
		);
	}

	private static Stream<Arguments> provideUserAndClientsLDP() {
		return Stream.of(
				getArguments(getUserModel("e@mail.org", "Happy", "User"),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString()),
										List.of("MyRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult<>(
								Map.of("email", "e@mail.org", "familyName", "User", "firstName", "Happy", "roles",
										Set.of(new Role(Set.of("MyRole"), "did:key:1"))),
								"A valid Credential should have been returned.")
				),
				getArguments(getUserModel("e@mail.org", null, "User"),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString()),
										List.of("MyRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult<>(
								Map.of("email", "e@mail.org", "familyName", "User", "roles",
										Set.of(new Role(Set.of("MyRole"), "did:key:1"))),
								"A valid Credential should have been returned.")
				),
				getArguments(
						getUserModel("e@mail.org", null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString()),
										List.of("MyRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult<>(
								Map.of("email", "e@mail.org", "roles",
										Set.of(new Role(Set.of("MyRole"), "did:key:1"))),
								"A valid Credential should have been returned.")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString()),
										List.of("MyRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult<>(
								Map.of("roles",
										Set.of(new Role(Set.of("MyRole"), "did:key:1"))),
								"A valid Credential should have been returned.")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString()),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole"))),
						new ExpectedResult<>(
								Map.of("roles",
										Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"))),
								"Multiple roles should be included")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString()),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"))),
						new ExpectedResult<>(
								Map.of("roles",
										Set.of(new Role(Set.of("MyRole"), "did:key:1"))),
								"Only assigned roles should be included.")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString()),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
								getSiopClient("did:key:2",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString()),
										List.of("AnotherRole")),
								List.of(getRoleModel("AnotherRole"))),
						new ExpectedResult<>(
								Map.of("roles",
										Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"),
												new Role(Set.of("AnotherRole"), "did:key:2"))),
								"The request should contain roles from both clients")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString()),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
								getSiopClient("did:key:2",
										Map.of("vctypes_AnotherType", FormatVO.LDP_VC.toString()),
										List.of("AnotherRole")),
								List.of(getRoleModel("AnotherRole"))),
						new ExpectedResult<>(
								Map.of("roles",
										Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"))),
								"Only roles for supported clients should be included.")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString()),
										List.of("MyRole", "MySecondRole"),
										Map.of("more", "claims")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
								getSiopClient("did:key:2",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString()),
										List.of("AnotherRole"),
										Map.of("additional", "claim")),
								List.of(getRoleModel("AnotherRole"))),
						new ExpectedResult<>(
								Map.of("roles",
										Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"),
												new Role(Set.of("AnotherRole"), "did:key:2")),
										"additional", "claim", "more", "claims"),
								"Additional claims should be included.")
				),
				getArguments(
						getUserModel(null, null, null),
						Map.of(getSiopClient("did:key:1",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString()),
										List.of("MyRole", "MySecondRole")),
								List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
								getSiopClient("did:key:2",
										Map.of("vctypes_MyType", FormatVO.LDP_VC.toString()),
										List.of("AnotherRole"),
										Map.of("additional", "claim")),
								List.of(getRoleModel("AnotherRole"))),
						new ExpectedResult<>(
								Map.of("additional", "claim", "roles",
										Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"),
												new Role(Set.of("AnotherRole"), "did:key:2"))),
								"Additional claims should be included.")
				)
		);
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
		// use answer to allow multiple invocations
		when(userModel.getAttributeStream(eq("firstName"))).then(f -> Stream.of(firstName));
		when(userModel.getAttributeStream(eq("familyName"))).then(f -> Stream.of(lastName));
		when(userModel.getAttributeStream(eq("email"))).then(f -> Stream.of(email));
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

	private static ClientModel getSiopClient(String clientId, Map<String, String> attributes, List<String> roles,
			Map<String, String> additionalClaims) {
		Stream<RoleModel> roleModelStream = roles.stream().map(role -> {
			RoleModel roleModel = mock(RoleModel.class);
			when(roleModel.getName()).thenReturn(role);
			return roleModel;
		});
		List<ProtocolMapperModel> mapperModels = new ArrayList<>();
		ProtocolMapperModel idMapperModel = mock(ProtocolMapperModel.class);
		when(idMapperModel.getProtocolMapper()).thenReturn(SIOP2SubjectIdMapper.MAPPER_ID);
		when(idMapperModel.getProtocol()).thenReturn(SIOP2LoginProtocolFactory.PROTOCOL_ID);
		when(idMapperModel.getConfig()).thenReturn(Map.of(SIOP2SubjectIdMapper.ID_KEY, "urn:uuid:dummy-id"));
		mapperModels.add(idMapperModel);

		if (clientId != null) {
			ProtocolMapperModel roleMapperModel = mock(ProtocolMapperModel.class);
			when(roleMapperModel.getProtocol()).thenReturn(SIOP2LoginProtocolFactory.PROTOCOL_ID);
			when(roleMapperModel.getProtocolMapper()).thenReturn(SIOP2TargetRoleMapper.MAPPER_ID);
			when(roleMapperModel.getConfig()).thenReturn(
					Map.of(SIOP2TargetRoleMapper.SUBJECT_PROPERTY_CONFIG_KEY, "roles",
							SIOP2TargetRoleMapper.CLIENT_CONFIG_KEY, clientId));
			mapperModels.add(roleMapperModel);
		}

		ProtocolMapperModel familyNameMapper = mock(ProtocolMapperModel.class);
		when(familyNameMapper.getProtocolMapper()).thenReturn(SIOP2UserAttributeMapper.MAPPER_ID);
		when(familyNameMapper.getProtocol()).thenReturn(SIOP2LoginProtocolFactory.PROTOCOL_ID);
		when(familyNameMapper.getConfig()).thenReturn(Map.of(SIOP2UserAttributeMapper.USER_ATTRIBUTE_KEY, "familyName",
				SIOP2UserAttributeMapper.SUBJECT_PROPERTY_CONFIG_KEY, "familyName",
				SIOP2UserAttributeMapper.AGGREGATE_ATTRIBUTES_KEY, "false"));
		mapperModels.add(familyNameMapper);

		ProtocolMapperModel firstNameMapper = mock(ProtocolMapperModel.class);
		when(firstNameMapper.getProtocolMapper()).thenReturn(SIOP2UserAttributeMapper.MAPPER_ID);
		when(firstNameMapper.getProtocol()).thenReturn(SIOP2LoginProtocolFactory.PROTOCOL_ID);
		when(firstNameMapper.getConfig()).thenReturn(Map.of(SIOP2UserAttributeMapper.USER_ATTRIBUTE_KEY, "firstName",
				SIOP2UserAttributeMapper.SUBJECT_PROPERTY_CONFIG_KEY, "firstName",
				SIOP2UserAttributeMapper.AGGREGATE_ATTRIBUTES_KEY, "false"));
		mapperModels.add(firstNameMapper);

		ProtocolMapperModel emailMapper = mock(ProtocolMapperModel.class);
		when(emailMapper.getProtocolMapper()).thenReturn(SIOP2UserAttributeMapper.MAPPER_ID);
		when(emailMapper.getProtocol()).thenReturn(SIOP2LoginProtocolFactory.PROTOCOL_ID);
		when(emailMapper.getConfig()).thenReturn(Map.of(SIOP2UserAttributeMapper.USER_ATTRIBUTE_KEY, "email",
				SIOP2UserAttributeMapper.SUBJECT_PROPERTY_CONFIG_KEY, "email",
				SIOP2UserAttributeMapper.AGGREGATE_ATTRIBUTES_KEY, "false"));
		mapperModels.add(emailMapper);

		additionalClaims.entrySet().forEach(entry -> {
			ProtocolMapperModel claimMapper = mock(ProtocolMapperModel.class);
			when(claimMapper.getProtocolMapper()).thenReturn(SIOP2StaticClaimMapper.MAPPER_ID);
			when(claimMapper.getProtocol()).thenReturn(SIOP2LoginProtocolFactory.PROTOCOL_ID);
			when(claimMapper.getConfig()).thenReturn(Map.of(SIOP2StaticClaimMapper.STATIC_CLAIM_KEY, entry.getValue(),
					SIOP2StaticClaimMapper.SUBJECT_PROPERTY_CONFIG_KEY, entry.getKey()));
			mapperModels.add(claimMapper);
		});

		ClientModel clientA = mock(ClientModel.class);
		when(clientA.getProtocol()).thenReturn(SIOP2LoginProtocolFactory.PROTOCOL_ID);
		when(clientA.getClientId()).thenReturn(clientId);
		when(clientA.getAttributes()).thenReturn(attributes);
		when(clientA.getProtocolMappersStream()).thenReturn(mapperModels.stream());
		when(clientA.getRolesStream()).thenReturn(roleModelStream);
		return clientA;
	}

	private static ClientModel getSiopClient(String clientId, Map<String, String> attributes, List<String> roles) {
		return getSiopClient(clientId, attributes, roles, Map.of());
	}

	private static ClientModel getSiopClient(Map<String, String> attributes) {
		return getSiopClient(null, attributes, List.of());
	}
}