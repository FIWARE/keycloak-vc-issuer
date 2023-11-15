package org.fiware.keycloak;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import id.walt.custodian.WaltIdCustodian;
import id.walt.sdjwt.JwtVerificationResult;
import id.walt.servicematrix.BaseService;
import id.walt.servicematrix.ServiceRegistry;
import id.walt.servicematrix.utils.ReflectionUtils;
import id.walt.services.crypto.SunCryptoService;
import id.walt.services.jwt.WaltIdJwtService;
import id.walt.services.key.WaltIdKeyService;
import id.walt.services.vc.WaltIdJsonLdCredentialService;
import id.walt.services.vc.WaltIdJwtCredentialService;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import kotlin.reflect.KClass;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.fiware.keycloak.model.ErrorResponse;
import org.fiware.keycloak.model.ErrorType;
import org.fiware.keycloak.model.Role;
import org.fiware.keycloak.model.SupportedCredential;
import org.fiware.keycloak.model.TokenResponse;
import org.fiware.keycloak.model.VCClaims;
import org.fiware.keycloak.model.VCConfig;
import org.fiware.keycloak.model.VCData;
import org.fiware.keycloak.model.VCRequest;
import org.fiware.keycloak.model.walt.CredentialDisplay;
import org.fiware.keycloak.model.walt.CredentialMetadata;
import org.fiware.keycloak.model.walt.FormatObject;
import org.fiware.keycloak.model.walt.IssuerDisplay;
import org.fiware.keycloak.model.walt.ProofType;
import org.fiware.keycloak.model.walt.CredentialOfferURI;
import org.fiware.keycloak.oidcvc.model.CredentialIssuerVO;
import org.fiware.keycloak.oidcvc.model.CredentialRequestVO;
import org.fiware.keycloak.oidcvc.model.CredentialResponseVO;
import org.fiware.keycloak.oidcvc.model.CredentialsOfferVO;
import org.fiware.keycloak.oidcvc.model.DisplayObjectVO;
import org.fiware.keycloak.oidcvc.model.ErrorResponseVO;
import org.fiware.keycloak.oidcvc.model.FormatVO;
import org.fiware.keycloak.oidcvc.model.PreAuthorizedGrantVO;
import org.fiware.keycloak.oidcvc.model.PreAuthorizedVO;
import org.fiware.keycloak.oidcvc.model.ProofTypeVO;
import org.fiware.keycloak.oidcvc.model.ProofVO;
import org.fiware.keycloak.oidcvc.model.SupportedCredentialVO;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.Time;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCWellKnownProvider;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.utils.OAuth2Code;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.urls.UrlType;

import javax.validation.constraints.NotNull;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.fiware.keycloak.SIOP2ClientRegistrationProvider.VC_TYPES_PREFIX;

/**
 * Realm-Resource to provide functionality for issuing VerifiableCredentials to users, depending on their roles in
 * registered SIOP-2 clients
 */
public class VCIssuerRealmResourceProvider implements RealmResourceProvider {

	private static final Logger LOGGER = Logger.getLogger(VCIssuerRealmResourceProvider.class);
	private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ISO_DATE_TIME
			.withZone(ZoneId.of(ZoneOffset.UTC.getId()));

	public static final String LD_PROOF_TYPE = "LD_PROOF";
	public static final String CREDENTIAL_PATH = "credential";
	public static final String TYPE_VERIFIABLE_CREDENTIAL = "VerifiableCredential";
	public static final String GRANT_TYPE_PRE_AUTHORIZED_CODE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
	private static final String ACCESS_CONTROL_HEADER = "Access-Control-Allow-Origin";

	private final KeycloakSession session;
	public static final String SUBJECT_DID = "subjectDid";
	private final String issuerDid;
	private final AppAuthManager.BearerTokenAuthenticator bearerTokenAuthenticator;
	private final WaltIdClient waltIdClient;
	private final ObjectMapper objectMapper;
	private final Clock clock;

	public VCIssuerRealmResourceProvider(KeycloakSession session, String issuerDid, WaltIdClient waltIdClient,
			AppAuthManager.BearerTokenAuthenticator authenticator,
			ObjectMapper objectMapper, Clock clock) {
		this.session = session;
		this.issuerDid = issuerDid;
		this.waltIdClient = waltIdClient;
		this.bearerTokenAuthenticator = authenticator;
		this.objectMapper = objectMapper;
		this.clock = clock;
		registerServices();
	}

	// register services used by the waltid ssikit
	private void registerServices() {
		ServiceRegistry.INSTANCE.registerService(WaltIdJsonLdCredentialService.Companion.getService(),
				(KClass<? extends BaseService>) ReflectionUtils.INSTANCE.getKClassByName(
						"id.walt.services.vc.JsonLdCredentialService"));
		ServiceRegistry.INSTANCE.registerService(WaltIdJwtCredentialService.Companion.getService(),
				(KClass<? extends BaseService>) ReflectionUtils.INSTANCE.getKClassByName(
						"id.walt.services.vc.JwtCredentialService"));
		ServiceRegistry.INSTANCE.registerService(SunCryptoService.Companion.getService(),
				(KClass<? extends BaseService>) ReflectionUtils.INSTANCE.getKClassByName(
						"id.walt.services.crypto.CryptoService"));
		ServiceRegistry.INSTANCE.registerService(WaltIdKeyService.Companion.getService(),
				(KClass<? extends BaseService>) ReflectionUtils.INSTANCE.getKClassByName(
						"id.walt.services.key.KeyService"));
		ServiceRegistry.INSTANCE.registerService(WaltIdJwtService.Companion.getService(),
				(KClass<? extends BaseService>) ReflectionUtils.INSTANCE.getKClassByName(
						"id.walt.services.jwt.JwtService"));
		ServiceRegistry.INSTANCE.registerService(WaltIdCustodian.Companion.getService(),
				(KClass<? extends BaseService>) ReflectionUtils.INSTANCE.getKClassByName(
						"id.walt.custodian.Custodian"));
	}

	@Override
	public Object getResource() {
		return this;
	}

	@Override
	public void close() {
		// no specific resources to close.
	}

	/**
	 * Returns the did used by Keycloak to issue credentials
	 *
	 * @return the did
	 */
	@GET
	@Path("/issuer")
	@Produces(MediaType.TEXT_PLAIN)
	public Response getIssuerDid() {
		return Response.ok().entity(issuerDid).header(ACCESS_CONTROL_HEADER, "*").build();
	}

	/**
	 * Returns a list of types supported by this realm-resource. Will evaluate all registered SIOP-2 clients and return
	 * there supported types. A user can request credentials for all of them.
	 *
	 * @return the list of supported VC-Types by this realm.
	 */
	@GET
	@Path("{issuer-did}/types")
	@Produces(MediaType.APPLICATION_JSON)
	public List<SupportedCredential> getTypes(@PathParam("issuer-did") String issuerDidParam) {
		assertIssuerDid(issuerDidParam);
		UserModel userModel = getUserModel(
				new NotAuthorizedException("Types is only available to authorized users."));

		LOGGER.debugf("User is {}", userModel.getId());

		return getCredentialsFromModels(getClientModelsFromSession());
	}

	// filter the client models for supported verifable credentials
	private List<SupportedCredential> getCredentialsFromModels(List<ClientModel> clientModels) {
		return List.copyOf(clientModels.stream()
				.map(ClientModel::getAttributes)
				.filter(Objects::nonNull)
				.flatMap(attrs -> attrs.entrySet().stream())
				.filter(attr -> attr.getKey().startsWith(VC_TYPES_PREFIX))
				.flatMap(entry -> mapAttributeEntryToSc(entry).stream())
				.collect(Collectors.toSet()));
	}

	// return the current usermodel
	private UserModel getUserModel(WebApplicationException errorResponse) {
		return getAuthResult(errorResponse).getUser();
	}

	// return the current usersession model
	private UserSessionModel getUserSessionModel() {
		return getAuthResult(new BadRequestException(getErrorResponse(ErrorType.INVALID_TOKEN))).getSession();
	}

	private AuthenticationManager.AuthResult getAuthResult() {
		return getAuthResult(new BadRequestException(getErrorResponse(ErrorType.INVALID_TOKEN)));
	}

	// get the auth result from the authentication manager
	private AuthenticationManager.AuthResult getAuthResult(WebApplicationException errorResponse) {
		AuthenticationManager.AuthResult authResult = bearerTokenAuthenticator.authenticate();
		if (authResult == null) {
			throw errorResponse;
		}
		return authResult;
	}

	private UserModel getUserModel() {
		return getUserModel(new BadRequestException(getErrorResponse(ErrorType.INVALID_TOKEN)));
	}

	// assert that the given string is the configured issuer did
	private void assertIssuerDid(String requestedIssuerDid) {
		if (!requestedIssuerDid.equals(issuerDid)) {
			throw new NotFoundException("No such issuer exists.");
		}
	}

	/**
	 * Returns the meta data of the issuer.
	 */
	@GET
	@Path("{issuer-did}/.well-known/openid-credential-issuer")
	@Produces({ MediaType.APPLICATION_JSON })
	@ApiOperation(value = "Return the issuer metadata", notes = "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-", tags = {})
	@ApiResponses(value = {
			@ApiResponse(code = 200, message = "The credentials issuer metadata", response = CredentialIssuerVO.class) })
	public Response getIssuerMetadata(@PathParam("issuer-did") String issuerDidParam) {
		LOGGER.info("Retrieve issuer meta data");
		assertIssuerDid(issuerDidParam);

		KeycloakContext currentContext = session.getContext();

		return Response.ok().entity(new CredentialIssuerVO()
						.credentialIssuer(getIssuer())
						.credentialEndpoint(getCredentialEndpoint())
						.credentialsSupported(getSupportedCredentials(currentContext)))
				.header(ACCESS_CONTROL_HEADER, "*").build();
	}

	private String getRealmResourcePath() {
		KeycloakContext currentContext = session.getContext();
		String realm = currentContext.getRealm().getName();
		String backendUrl = currentContext.getUri(UrlType.BACKEND).getBaseUri().toString();
		if (backendUrl.endsWith("/")) {
			return String.format("%srealms/%s", backendUrl, realm);
		}
		return String.format("%s/realms/%s", backendUrl, realm);
	}

	private String getCredentialEndpoint() {

		return getIssuer() + "/" + CREDENTIAL_PATH;
	}

	private String getIssuer() {
		return String.format("%s/%s/%s", getRealmResourcePath(),
				VCIssuerRealmResourceProviderFactory.ID,
				issuerDid);
	}

	/**
	 * Returns the openid-configuration of the issuer.
	 * OIDC4VCI wallets expect the openid-configuration below the issuers root, thus we provide it here in addition to its standard keycloak path.
	 */
	@GET
	@Path("{issuer-did}/.well-known/openid-configuration")
	@Produces({ MediaType.APPLICATION_JSON })
	public Response getOIDCConfig(@PathParam("issuer-did") String issuerDidParam) {
		LOGGER.info("Get OIDC config.");
		assertIssuerDid(issuerDidParam);
		// some wallets use the openid-config well-known to also gather the issuer metadata. In
		// the future(when everyone uses .well-known/openid-credential-issuer), that can be removed.
		Map<String, Object> configAsMap = objectMapper.convertValue(
				new OIDCWellKnownProvider(session, null, false).getConfig(),
				Map.class);

		List<String> supportedGrantTypes = Optional.ofNullable(configAsMap.get("grant_types_supported"))
				.map(grantTypesObject -> objectMapper.convertValue(
						grantTypesObject, new TypeReference<List<String>>() {
						})).orElse(new ArrayList<>());
		// newly invented by OIDC4VCI and supported by this implementation
		supportedGrantTypes.add(GRANT_TYPE_PRE_AUTHORIZED_CODE);
		configAsMap.put("grant_types_supported", supportedGrantTypes);
		configAsMap.put("token_endpoint", getIssuer() + "/token");
		configAsMap.put("credential_endpoint", getCredentialEndpoint());
		IssuerDisplay issuerDisplay = new IssuerDisplay();
		issuerDisplay.display.add(
				new DisplayObjectVO()
						.name(String.format("Keycloak-Credentials Issuer - %s", issuerDid))
						.locale("en_US"));
		configAsMap.put("credential_issuer", issuerDisplay);

		CredentialMetadata credentialMetadata = new CredentialMetadata();
		credentialMetadata.setDisplay(List.of(new CredentialDisplay("Verifiable Credential")));
		FormatObject ldpVC = new FormatObject(new ArrayList<>());
		FormatObject jwtVC = new FormatObject(new ArrayList<>());

		getCredentialsFromModels(session.getContext().getRealm().getClientsStream().collect(Collectors.toList()))
				.forEach(supportedCredential -> {
					if (supportedCredential.getFormat() == FormatVO.LDP_VC) {
						ldpVC.getTypes().add(supportedCredential.getType());
					} else {
						jwtVC.getTypes().add(supportedCredential.getType());
					}
				});
		credentialMetadata.setFormats(Map.of(FormatVO.LDP_VC.toString(), ldpVC, FormatVO.JWT_VC.toString(), jwtVC));
		configAsMap.put("credentials_supported", Map.of(TYPE_VERIFIABLE_CREDENTIAL, credentialMetadata));
		return Response.ok()
				.entity(configAsMap)
				.header(ACCESS_CONTROL_HEADER, "*")
				.build();
	}

	/**
	 * Provides URI to the OIDC4VCI compliant credentials offer
	 */
	@GET
	@Path("{issuer-did}/credential-offer-uri")
	@Produces({ MediaType.APPLICATION_JSON })
	public Response getCredentialOfferURI(@PathParam("issuer-did") String issuerDidParam,
			@QueryParam("type") String vcType, @QueryParam("format") FormatVO format) {

		LOGGER.infof("Get an offer for %s - %s", vcType, format);
		assertIssuerDid(issuerDidParam);
		// workaround to support implementations not differentiating json & json-ld
		if (format == FormatVO.JWT_VC) {
			// validate that the user is able to get the offered credentials
			getClientsOfType(vcType, FormatVO.JWT_VC_JSON);
		} else {
			getClientsOfType(vcType, format);
		}

		SupportedCredential offeredCredential = new SupportedCredential(vcType, format);
		Instant now = clock.instant();
		JsonWebToken token = new JsonWebToken()
				.id(UUID.randomUUID().toString())
				.subject(getUserModel().getId())
				.nbf(now.getEpochSecond())
				//maybe configurable in the future, needs to be short lived
				.exp(now.plus(Duration.of(30, ChronoUnit.SECONDS)).getEpochSecond());
		token.setOtherClaims("offeredCredential", new SupportedCredential(vcType, format));

		String nonce = generateAuthorizationCode();

		AuthenticationManager.AuthResult authResult = getAuthResult();
		UserSessionModel userSessionModel = getUserSessionModel();

		AuthenticatedClientSessionModel clientSession = userSessionModel.
				getAuthenticatedClientSessionByClient(
						authResult.getClient().getId());
		try {
			clientSession.setNote(nonce, objectMapper.writeValueAsString(offeredCredential));
		} catch (JsonProcessingException e) {
			LOGGER.errorf("Could not convert POJO to JSON: %s", e.getMessage());
			throw new BadRequestException(getErrorResponse(ErrorType.INVALID_REQUEST));
		}

		CredentialOfferURI credentialOfferURI = new CredentialOfferURI(getIssuer(), nonce);

		LOGGER.infof("Responding with nonce: %s", nonce);
		return Response.ok()
				.entity(credentialOfferURI)
				.header(ACCESS_CONTROL_HEADER, "*")
				.build();

	}

	/**
	 * Provides an OIDC4VCI compliant credentials offer
	 */
	@GET
	@Path("{issuer-did}/credential-offer/{nonce}")
	@Produces({ MediaType.APPLICATION_JSON })
	public Response getCredentialOffer(@PathParam("issuer-did") String issuerDidParam,
									   @PathParam("nonce") String nonce) {
			LOGGER.infof("Get an offer from issuer %s for nonce %s", issuerDidParam, nonce);
		assertIssuerDid(issuerDidParam);

		OAuth2CodeParser.ParseResult result = parseAuthorizationCode(nonce);

		SupportedCredential offeredCredential;
		try {
			offeredCredential = objectMapper.readValue(result.getClientSession().getNote(nonce),
					SupportedCredential.class);
			LOGGER.infof("Creating an offer for %s - %s", offeredCredential.getType(),
					offeredCredential.getFormat());
			result.getClientSession().removeNote(nonce);
		} catch (JsonProcessingException e) {
			LOGGER.errorf("Could not convert JSON to POJO: %s", e);
			throw new BadRequestException(getErrorResponse(ErrorType.INVALID_REQUEST));
		}

        String preAuthorizedCode = generateAuthorizationCodeForClientSession(result.getClientSession());
		CredentialsOfferVO theOffer = new CredentialsOfferVO()
				.credentialIssuer(getIssuer())
				.credentials(List.of(offeredCredential))
				.grants(new PreAuthorizedGrantVO().
						urnColonIetfColonParamsColonOauthColonGrantTypeColonPreAuthorizedCode(
								new PreAuthorizedVO().preAuthorizedCode(preAuthorizedCode)
										.userPinRequired(false)));

		LOGGER.infof("Responding with offer: %s", theOffer);
		return Response.ok()
				.entity(theOffer)
				.header(ACCESS_CONTROL_HEADER, "*")
				.build();
	}

	/**
	 * Token endpoint, as defined by the standard. Allows to exchange the pre-authorized-code with an access-token
	 */
	@POST
	@Path("{issuer-did}/token")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response exchangeToken(@PathParam("issuer-did") String issuerDidParam,
			@FormParam("grant_type") String grantType,
			@FormParam("code") String code,
			@FormParam("pre-authorized_code") String preauth) {
		assertIssuerDid(issuerDidParam);
		LOGGER.infof("Received token request %s - %s - %s.", grantType, code, preauth);

		if (Optional.ofNullable(grantType).map(gt -> !gt.equals(GRANT_TYPE_PRE_AUTHORIZED_CODE))
				.orElse(preauth == null)) {
			throw new BadRequestException(getErrorResponse(ErrorType.INVALID_TOKEN));
		}
		// some (not fully OIDC4VCI compatible) wallets send the preauthorized code as an alternative parameter
		String codeToUse = Optional.ofNullable(code).orElse(preauth);

		OAuth2CodeParser.ParseResult result = parseAuthorizationCode(codeToUse);
		AccessToken accessToken = new TokenManager().createClientAccessToken(session,
				result.getClientSession().getRealm(),
				result.getClientSession().getClient(),
				result.getClientSession().getUserSession().getUser(),
				result.getClientSession().getUserSession(),
				DefaultClientSessionContext.fromClientSessionAndScopeParameter(result.getClientSession(),
						OAuth2Constants.SCOPE_OPENID, session));

		String encryptedToken = session.tokens().encodeAndEncrypt(accessToken);
		String tokenType = "bearer";
		long expiresIn = accessToken.getExp() - Time.currentTime();

		LOGGER.infof("Successfully returned the token: %s.", encryptedToken);
		return Response.ok().entity(new TokenResponse(encryptedToken, tokenType, expiresIn, null, null))
				.header(ACCESS_CONTROL_HEADER, "*")
				.build();
	}

	private OAuth2CodeParser.ParseResult parseAuthorizationCode(String codeToUse) throws BadRequestException {
		EventBuilder eventBuilder = new EventBuilder(session.getContext().getRealm(), session,
				session.getContext().getConnection());
		OAuth2CodeParser.ParseResult result = OAuth2CodeParser.parseCode(session, codeToUse,
				session.getContext().getRealm(),
				eventBuilder);
		if (result.isExpiredCode() || result.isIllegalCode()) {
			throw new BadRequestException(getErrorResponse(ErrorType.INVALID_TOKEN));
		}
		return result;
	}

	private String generateAuthorizationCode() {
		AuthenticationManager.AuthResult authResult = getAuthResult();
		UserSessionModel userSessionModel = getUserSessionModel();
		AuthenticatedClientSessionModel clientSessionModel = userSessionModel.
				getAuthenticatedClientSessionByClient(authResult.getClient().getId());
		return generateAuthorizationCodeForClientSession(clientSessionModel);
	}

	private String generateAuthorizationCodeForClientSession(AuthenticatedClientSessionModel clientSessionModel) {
		int expiration = Time.currentTime() + clientSessionModel.getUserSession().getRealm().getAccessCodeLifespan();

		String codeId = UUID.randomUUID().toString();
		String nonce = UUID.randomUUID().toString();
		OAuth2Code oAuth2Code = new OAuth2Code(codeId, expiration, nonce, null, null, null, null,
				clientSessionModel.getUserSession().getId());

		return OAuth2CodeParser.persistCode(session, clientSessionModel, oAuth2Code);
	}

	private Response getErrorResponse(ErrorType errorType) {
		return Response.status(Response.Status.BAD_REQUEST).entity(new ErrorResponse(errorType.getValue())).build();
	}

	/**
	 * Options endpoint to serve the cors-preflight requests.
	 * Since we cannot know the address of the requesting wallets in advance, we have to accept all origins.
	 */
	@OPTIONS
	@Path("{any: .*}")
	public Response optionCorsResponse() {
		return Response.ok().header(ACCESS_CONTROL_HEADER, "*")
				.header("Access-Control-Allow-Methods", "POST,GET,OPTIONS")
				.header("Access-Control-Allow-Headers", "Content-Type,Authorization")
				.build();
	}

	/**
	 * Returns a verifiable credential of the given type, containing the information and roles assigned to the
	 * authenticated user.
	 * In order to support the often used retrieval method by wallets, the token can also be provided as a
	 * query-parameter. If the parameter is empty, the token is taken from the authorization-header.
	 *
	 * @param vcType type of the VerifiableCredential to be returend.
	 * @param token  optional JWT to be used instead of retrieving it from the header.
	 * @return the vc.
	 */
	@GET
	@Path("{issuer-did}/")
	@Produces(MediaType.APPLICATION_JSON)
	public Response issueVerifiableCredential(@PathParam("issuer-did") String issuerDidParam,
			@QueryParam("type") String vcType, @QueryParam("token") String
			token) {
		LOGGER.debugf("Get a VC of type %s. Token parameter is %s.", vcType, token);
		assertIssuerDid(issuerDidParam);
		return Response.ok().
				entity(getCredential(vcType, FormatVO.LDP_VC, token)).
				header(ACCESS_CONTROL_HEADER, "*").
				build();
	}

	/**
	 * Requests a credential from the issuer
	 */
	@POST
	@Path("{issuer-did}/" + CREDENTIAL_PATH)
	@Consumes({ "application/json" })
	@Produces({ "application/json" })
	@ApiOperation(value = "Request a credential from the issuer", notes = "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request", tags = {})
	@ApiResponses(value = {
			@ApiResponse(code = 200, message = "Credential Response can be Synchronous or Deferred. The Credential Issuer MAY be able to immediately issue a requested Credential and send it to the Client. In other cases, the Credential Issuer MAY NOT be able to immediately issue a requested Credential and would want to send an acceptance_token parameter to the Client to be used later to receive a Credential when it is ready.", response = CredentialResponseVO.class),
			@ApiResponse(code = 400, message = "When the Credential Request is invalid or unauthorized, the Credential Issuer responds the error response", response = ErrorResponseVO.class) })
	public Response requestCredential(@PathParam("issuer-did") String issuerDidParam,
			CredentialRequestVO credentialRequestVO) {
		assertIssuerDid(issuerDidParam);
		LOGGER.infof("Received credentials request %s.", credentialRequestVO);

		List<String> types = new ArrayList<>(Objects.requireNonNull(Optional.ofNullable(credentialRequestVO.getTypes())
				.orElseGet(() -> {
					try {
						return objectMapper.readValue(credentialRequestVO.getType(), new TypeReference<>() {
                        });
					} catch (JsonProcessingException e) {
						LOGGER.warnf("Was not able to read the type parameter: %s", credentialRequestVO.getType(), e);
						return null;
					}
				})));

		// remove the static type
		types.remove(TYPE_VERIFIABLE_CREDENTIAL);

		if (types.size() != 1) {
			LOGGER.infof("Credential request contained multiple types. Req: %s", credentialRequestVO);
			throw new BadRequestException(getErrorResponse(ErrorType.INVALID_REQUEST));
		}
		if (credentialRequestVO.getProof() != null) {
			validateProof(credentialRequestVO.getProof());
		}
		FormatVO requestedFormat = credentialRequestVO.getFormat();
		// workaround to support implementations not differentiating json & json-ld
		if (requestedFormat == FormatVO.JWT_VC) {
			requestedFormat = FormatVO.JWT_VC_JSON;
		}

		String vcType = types.get(0);

		CredentialResponseVO responseVO = new CredentialResponseVO();
		// keep the originally requested here.
		responseVO.format(credentialRequestVO.getFormat());

		String credentialString = getCredential(vcType, credentialRequestVO.getFormat(), null);
		switch (requestedFormat) {
			case LDP_VC: {
				try {
					// formats the string to an object and to valid json
					Object credentialObject = objectMapper.readValue(credentialString, Object.class);
					responseVO.setCredential(credentialObject);
				} catch (JsonProcessingException e) {
					LOGGER.warnf("Was not able to format credential %s.", credentialString, e);
					throw new BadRequestException(getErrorResponse(ErrorType.UNSUPPORTED_CREDENTIAL_TYPE));
				}
				break;
			}
			case JWT_VC_JSON: {
				responseVO.setCredential(credentialString);
				break;
			}
			default: {
				LOGGER.infof("Credential with unsupported format %s was requested.", requestedFormat.toString());
				throw new BadRequestException(getErrorResponse(ErrorType.UNSUPPORTED_CREDENTIAL_TYPE));
			}

		}
		return Response.ok().entity(responseVO)
				.header(ACCESS_CONTROL_HEADER, "*").build();
	}

	private void validateProof(ProofVO proofVO) {
		if (proofVO.getProofType() != ProofTypeVO.JWT) {
			LOGGER.warn("We currently only support JWT proofs.");
			throw new BadRequestException(getErrorResponse(ErrorType.INVALID_OR_MISSING_PROOF));
		}
		var jwtService = WaltIdJwtService.Companion.getService();
		JwtVerificationResult verificationResult = jwtService.verify(proofVO.getJwt());
		if (!verificationResult.getVerified()) {
			LOGGER.warnf("Signature of the provided jwt-proof was not valid: %s", proofVO.getJwt());
			throw new BadRequestException(getErrorResponse(ErrorType.INVALID_OR_MISSING_PROOF));
		}
	}

	private String getCredential(String vcType, FormatVO format, String token) {
		UserModel userModel = getUserFromSession(Optional.ofNullable(token));

		List<ClientModel> clients = getClientsOfType(vcType, format);

		// get the smallest expiry, to not generate VCs with to long lifetimes.
		Optional<Long> optionalMinExpiry = clients.stream()
				.map(ClientModel::getAttributes)
				.filter(Objects::nonNull)
				.map(attributes -> attributes.get(SIOP2ClientRegistrationProvider.EXPIRY_IN_MIN))
				.filter(Objects::nonNull)
				.map(Long::parseLong)
				.sorted()
				.findFirst();
		optionalMinExpiry.ifPresentOrElse(
				minExpiry -> LOGGER.debugf("The min expiry is %d.", minExpiry),
				() -> LOGGER.debugf("No min-expiry found. VC will not expire."));

		Set<Role> roles = clients.stream()
				.map(cm -> new ClientRoleModel(cm.getClientId(),
						userModel.getClientRoleMappingsStream(cm).collect(Collectors.toList())))
				.map(this::toRolesClaim)
				.filter(role -> !role.getNames().isEmpty())
				.collect(Collectors.toSet());

		ProofType proofType = ProofType.JWT;
		if (format == FormatVO.LDP_VC) {
			proofType = ProofType.LD_PROOF;
		}

		VCRequest vcRequest = getVCRequest(vcType, proofType, userModel, clients, roles, optionalMinExpiry);
		LOGGER.infof("Request is %s.", vcRequest);
		return waltIdClient.getVCFromWaltId(vcRequest);

	}

	@NotNull
	private List<ClientModel> getClientsOfType(String vcType, FormatVO format) {
		LOGGER.debugf("Retrieve all clients of type %s, supporting format %s", vcType, format.toString());
		if (format == FormatVO.JWT_VC) {
			// backward compat
			format = FormatVO.JWT_VC_JSON;
		}
		String formatString = format.toString();
		Optional.ofNullable(vcType).filter(type -> !type.isEmpty()).orElseThrow(() -> {
			LOGGER.info("No VC type was provided.");
			return new BadRequestException("No VerifiableCredential-Type was provided in the request.");
		});

		String prefixedType = String.format("%s%s", VC_TYPES_PREFIX, vcType);
		LOGGER.infof("Looking for client supporting %s with format %s", prefixedType, formatString);
		List<ClientModel> vcClients = getClientModelsFromSession().stream()
				.filter(clientModel -> Optional.ofNullable(clientModel.getAttributes())
						.filter(attributes -> attributes.containsKey(prefixedType))
						.filter(attributes -> Arrays.asList(attributes.get(prefixedType).split(","))
								.contains(formatString))
						.isPresent())
				.collect(Collectors.toList());

		if (vcClients.isEmpty()) {
			LOGGER.infof("No SIOP-2-Client supporting type %s registered.", vcType);
			throw new BadRequestException(getErrorResponse(ErrorType.UNSUPPORTED_CREDENTIAL_TYPE));
		}
		return vcClients;
	}

	@NotNull
	private UserModel getUserFromSession(Optional<String> optionalToken) {
		LOGGER.debugf("Extract user form session. Realm in context is %s.", session.getContext().getRealm());
		// set the token in the context if its specifically provided. If empty, the authorization header will
		// automatically be evaluated
		optionalToken.ifPresent(bearerTokenAuthenticator::setTokenString);

		UserModel userModel = getUserModel();
		LOGGER.debugf("Authorized user is %s.", userModel.getId());
		return userModel;
	}

	@NotNull
	private List<ClientModel> getClientModelsFromSession() {
		return session.clients().getClientsStream(session.getContext().getRealm())
				.filter(clientModel -> clientModel.getProtocol() != null)
				.filter(clientModel -> clientModel.getProtocol().equals(SIOP2LoginProtocolFactory.PROTOCOL_ID))
				.collect(Collectors.toList());
	}

	@NotNull
	private Role toRolesClaim(ClientRoleModel crm) {
		Set<String> roleNames = crm
				.getRoleModels()
				.stream()
				.map(RoleModel::getName)
				.collect(Collectors.toSet());
		return new Role(roleNames, crm.getClientId());
	}

	@NotNull
	private VCRequest getVCRequest(String vcType, ProofType proofType, UserModel userModel, List<ClientModel> clients,
			Set<Role> roles,
			Optional<Long> optionalMinExpiry) {
		// only include non-null & non-empty claims
		var claimsBuilder = VCClaims.builder();

		LOGGER.infof("Will set roles %s", roles);
		List<String> claims = getClaimsToSet(vcType, clients);
		LOGGER.infof("Will set %s", claims);
		if (claims.contains("email")) {
			Optional.ofNullable(userModel.getEmail()).filter(email -> !email.isEmpty()).ifPresent(claimsBuilder::email);
		}
		if (claims.contains("firstName")) {
			Optional.ofNullable(userModel.getFirstName()).filter(firstName -> !firstName.isEmpty())
					.ifPresent(claimsBuilder::firstName);
		}
		if (claims.contains("familyName")) {
			Optional.ofNullable(userModel.getLastName()).filter(lastName -> !lastName.isEmpty())
					.ifPresent(claimsBuilder::familyName);
		}
		if (claims.contains("roles")) {
			Optional.ofNullable(roles).filter(rolesList -> !rolesList.isEmpty()).ifPresent(claimsBuilder::roles);
		}
		Map<String, String> additionalClaims = getAdditionalClaims(clients).map(claimsMap ->
				claimsMap.entrySet().stream().filter(entry -> claims.contains(entry.getKey()))
						.collect(Collectors.toMap(
								Map.Entry::getKey, Map.Entry::getValue))
		).orElse(Map.of());

		var vcConfigBuilder = VCConfig.builder();
		if (additionalClaims.containsKey(SUBJECT_DID)) {
			LOGGER.infof("Set subject did to %s", additionalClaims.get(SUBJECT_DID));
			vcConfigBuilder.subjectDid(additionalClaims.get(SUBJECT_DID));
			additionalClaims.remove(SUBJECT_DID);
		} else {
			// we have to set something
			vcConfigBuilder.subjectDid(UUID.randomUUID().toString());
		}

		claimsBuilder.additionalClaims(additionalClaims);
		VCClaims vcClaims = claimsBuilder.build();
		vcConfigBuilder.issuerDid(issuerDid)
				.proofType(proofType.toString());

		// TODO: reintroduce when walt api is fixed
		//		optionalMinExpiry
		//				.map(minExpiry -> Clock.systemUTC()
		//						.instant()
		//						.plus(Duration.of(minExpiry, ChronoUnit.MINUTES)))
		//				.map(FORMATTER::format)
		//				.ifPresent(vcConfigBuilder::expirationDate);

		VCConfig vcConfig = vcConfigBuilder.build();
		LOGGER.debugf("VC config is %s", vcConfig);
		return VCRequest.builder().templateId(vcType)
				.config(vcConfig)
				.credentialData(VCData.builder()
						.credentialSubject(vcClaims)
						.build())
				.build();
	}

	@NotNull
	private List<String> getClaimsToSet(String credentialType, List<ClientModel> clients) {
		String claims = clients.stream()
				.map(ClientModel::getAttributes)
				.filter(Objects::nonNull)
				.map(Map::entrySet)
				.flatMap(Set::stream)
				// get the claims
				.filter(entry -> entry.getKey().equals(String.format("%s_%s", credentialType, "claims")))
				.findFirst()
				.map(Map.Entry::getValue)
				.orElse("");
		LOGGER.infof("Should set %s for %s.", claims, credentialType);
		return Arrays.asList(claims.split(","));

	}

	@NotNull
	private Optional<Map<String, String>> getAdditionalClaims(List<ClientModel> clients) {
		Map<String, String> additionalClaims = clients.stream()
				.map(ClientModel::getAttributes)
				.filter(Objects::nonNull)
				.map(Map::entrySet)
				.flatMap(Set::stream)
				// only include the claims explicitly intended for vc
				.filter(entry -> entry.getKey().startsWith(SIOP2ClientRegistrationProvider.VC_CLAIMS_PREFIX))
				.collect(
						Collectors.toMap(
								// remove the prefix before sending it
								entry -> entry.getKey()
										.replaceFirst(SIOP2ClientRegistrationProvider.VC_CLAIMS_PREFIX, ""),
								// value is taken untouched if its unique
								Map.Entry::getValue,
								// if multiple values for the same key exist, we add them comma separated.
								// this needs to be improved, once more requirements are known.
								(entry1, entry2) -> {
									if (entry1.equals(entry2) || entry1.contains(entry2)) {
										return entry1;
									} else {
										return String.format("%s,%s", entry1, entry2);
									}
								}
						));
		if (additionalClaims.isEmpty()) {
			return Optional.empty();
		} else {
			return Optional.of(additionalClaims);
		}
	}

	private List<SupportedCredentialVO> getSupportedCredentials(KeycloakContext context) {

		return context.getRealm().getClientsStream()
				.flatMap(cm -> cm.getAttributes().entrySet().stream())
				.filter(entry -> entry.getKey().startsWith(VC_TYPES_PREFIX))
				.flatMap(entry -> mapAttributeEntryToScVO(entry).stream())
				.collect(Collectors.toList());

	}

	private List<SupportedCredential> mapAttributeEntryToSc(Map.Entry<String, String> typesEntry) {
		String type = typesEntry.getKey().replaceFirst(VC_TYPES_PREFIX, "");
		Set<FormatVO> supportedFormats = getFormatsFromString(typesEntry.getValue());
		return supportedFormats.stream().map(formatVO -> new SupportedCredential(type, formatVO))
				.collect(Collectors.toList());
	}

	private List<SupportedCredentialVO> mapAttributeEntryToScVO(Map.Entry<String, String> typesEntry) {
		String type = typesEntry.getKey().replaceFirst(VC_TYPES_PREFIX, "");
		Set<FormatVO> supportedFormats = getFormatsFromString(typesEntry.getValue());
		return supportedFormats.stream().map(formatVO -> {
					String id = buildIdFromType(formatVO, type);
					return new SupportedCredentialVO()
							.id(id)
							.format(formatVO)
							.types(List.of(type))
							.cryptographicBindingMethodsSupported(List.of("did"))
							.cryptographicSuitesSupported(List.of("Ed25519Signature2018"));
				}
		).collect(Collectors.toList());
	}

	private String buildIdFromType(FormatVO formatVO, String type) {
		return String.format("%s_%s", type, formatVO.toString());
	}

	private Set<FormatVO> getFormatsFromString(String formatString) {
		return Arrays.stream(formatString.split(",")).map(FormatVO::fromString).collect(Collectors.toSet());
	}

	@Getter
	@RequiredArgsConstructor
	private static class ClientRoleModel {
		private final String clientId;
		private final List<RoleModel> roleModels;
	}
}
