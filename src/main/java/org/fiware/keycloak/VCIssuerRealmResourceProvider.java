package org.fiware.keycloak;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.fiware.keycloak.model.ErrorResponse;
import org.fiware.keycloak.model.ErrorType;
import org.fiware.keycloak.model.Role;
import org.fiware.keycloak.model.VCClaims;
import org.fiware.keycloak.model.VCConfig;
import org.fiware.keycloak.model.VCData;
import org.fiware.keycloak.model.VCRequest;
import org.fiware.keycloak.oidcvc.model.CredentialIssuerVO;
import org.fiware.keycloak.oidcvc.model.CredentialRequestVO;
import org.fiware.keycloak.oidcvc.model.CredentialResponseVO;
import org.fiware.keycloak.oidcvc.model.CredentialVO;
import org.fiware.keycloak.oidcvc.model.ErrorResponseVO;
import org.fiware.keycloak.oidcvc.model.FormatVO;
import org.fiware.keycloak.oidcvc.model.SupportedCredentialVO;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.urls.UrlType;

import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
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
 * Real-Resource to provide functionality for issuing VerfiableCredentials to users, depending on there roles in
 * registered SIOP-2 clients
 */
public class VCIssuerRealmResourceProvider implements RealmResourceProvider {

	private static final Logger LOGGER = Logger.getLogger(VCIssuerRealmResourceProvider.class);
	private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ISO_DATE_TIME
			.withZone(ZoneId.of(ZoneOffset.UTC.getId()));

	public static final String LD_PROOF_TYPE = "LD_PROOF";
	public static final String CREDENTIAL_PATH = "credential";
	public static final String TYPE_VERIFIABLE_CREDENTIAL = "VerifiableCredential";

	private final KeycloakSession session;
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
	 * Returns a list of types supported by this realm-resource. Will evaluate all registered SIOP-2 clients and return
	 * there supported types. A user can request credentials for all of them.
	 *
	 * @return the list of supported VC-Types by this realm.
	 */
	@GET
	@Path("types")
	@Produces(MediaType.APPLICATION_JSON)
	public List<String> getTypes() {
		AuthenticationManager.AuthResult authResult = bearerTokenAuthenticator.authenticate();
		if (authResult == null) {
			throw new ErrorResponseException("unauthorized", "Types is only available to authorized users.",
					Response.Status.UNAUTHORIZED);
		}
		UserModel userModel = authResult.getUser();
		LOGGER.debugf("User is {}", userModel.getId());

		return List.copyOf(getClientModelsFromSession().stream()
				.map(ClientModel::getAttributes)
				.filter(Objects::nonNull)
				.flatMap(attrs -> attrs.entrySet().stream())
				.filter(attr -> attr.getKey().startsWith(VC_TYPES_PREFIX))
				.map(Map.Entry::getKey)
				.filter(Objects::nonNull)
				.map(type -> type.replaceFirst(VC_TYPES_PREFIX, ""))
				// collect to a set to remove duplicates
				.collect(Collectors.toSet()));

	}

	private Response getErrorResponse(ErrorType errorType) {
		return Response.status(Response.Status.BAD_REQUEST).entity(new ErrorResponse(errorType.getValue())).build();
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
	@Produces(MediaType.APPLICATION_JSON)
	public Response issueVerifiableCredential(@QueryParam("type") String vcType, @QueryParam("token") String token) {
		LOGGER.debugf("Get a VC of type %s. Token parameter is %s.", vcType, token);
		return Response.ok().entity(getCredential(vcType, FormatVO.LDP_VC, token))
				.header("Access-Control-Allow-Origin", "*").build();
	}

	@POST
	@Path(CREDENTIAL_PATH)
	@Consumes({ "application/json" })
	@Produces({ "application/json" })
	@ApiOperation(value = "Request a credential from the issuer", notes = "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request", tags = {})
	@ApiResponses(value = {
			@ApiResponse(code = 200, message = "Credential Response can be Synchronous or Deferred. The Credential Issuer MAY be able to immediately issue a requested Credential and send it to the Client. In other cases, the Credential Issuer MAY NOT be able to immediately issue a requested Credential and would want to send an acceptance_token parameter to the Client to be used later to receive a Credential when it is ready.", response = CredentialResponseVO.class),
			@ApiResponse(code = 400, message = "When the Credential Request is invalid or unauthorized, the Credential Issuer responds the error response", response = ErrorResponseVO.class) })
	public Response requestCredential(CredentialRequestVO credentialRequestVO) {
		List<String> types = credentialRequestVO.getTypes();
		// remove the static type
		types.remove(TYPE_VERIFIABLE_CREDENTIAL);

		if (types.size() != 1) {
			LOGGER.infof("Credential request contained multiple types. Req: %s", credentialRequestVO);
			throw new ErrorResponseException(getErrorResponse(ErrorType.INVALID_REQUEST));
		}
		if (credentialRequestVO.getProof() != null) {
			LOGGER.infof("Including requested proofs into the credential is currently unsupported.");
			throw new ErrorResponseException(getErrorResponse(ErrorType.INVALID_OR_MISSING_PROOF));
		}
		FormatVO requestedFormat = credentialRequestVO.getFormat();

		String vcType = types.get(0);

		CredentialResponseVO responseVO = new CredentialResponseVO();
		responseVO.format(requestedFormat);

		CredentialVO credentialVO = getCredential(vcType, credentialRequestVO.getFormat(), null);
		switch (requestedFormat) {
			case LDP_VC: {
				responseVO.setCredential(credentialVO);
				break;
			}
			case JWT_VC_JSON: {
				JsonWebToken jwt = new JsonWebToken()
						.id(UUID.randomUUID().toString())
						.issuer(issuerDid)
						.nbf(clock.instant().getEpochSecond());
				jwt.setOtherClaims("credential", credentialVO);
				responseVO.setCredential(session.tokens().encodeAndEncrypt(jwt));
				break;
			}
			default: {
				LOGGER.infof("Credential with unsupported format %s was requested.", requestedFormat.toString());
				throw new ErrorResponseException(getErrorResponse(ErrorType.UNSUPPORTED_CREDENTIAL_TYPE));
			}

		}
		return Response.ok().entity(responseVO)
				.header("Access-Control-Allow-Origin", "*").build();
	}

	private CredentialVO getCredential(String vcType, FormatVO format, String token) {
		UserModel userModel = getUserFromSession(Optional.ofNullable(token));

		List<ClientModel> clients = getClientsOfType(vcType, format);
		if (clients.isEmpty()) {
			LOGGER.infof("No client for type %s, supporting format %s found.", vcType, format.toString());
			throw new ErrorResponseException(getErrorResponse(ErrorType.UNSUPPORTED_CREDENTIAL_TYPE));
		}
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

		VCRequest vcRequest = getVCRequest(vcType, userModel, clients, roles, optionalMinExpiry);

		String response = waltIdClient.getVCFromWaltId(vcRequest);

		try {
			CredentialVO vc = objectMapper.readValue(response, CredentialVO.class);
			LOGGER.debugf("Respond with vc: %s", response);
			// the typical wallet will request with a CORS header and not accept responses without.
			return vc;
		} catch (JsonProcessingException e) {
			LOGGER.warn("Did not receive a valid credential.", e);
			throw new ErrorResponseException("bad_gateway",
					"Did not get a valid response from walt-id.",
					Response.Status.BAD_GATEWAY);
		}
	}

	@NotNull
	private List<ClientModel> getClientsOfType(String vcType, FormatVO format) {
		LOGGER.debugf("Retrieve all clients of type %s, supporting format %s", vcType, format.toString());
		Optional.ofNullable(vcType).filter(type -> !type.isEmpty()).orElseThrow(() -> {
			LOGGER.info("No VC type was provided.");
			return new ErrorResponseException("no_type_provided",
					"No VerifiableCredential-Type was provided in the request.",
					Response.Status.BAD_REQUEST);
		});

		String prefixedType = String.format("%s%s", VC_TYPES_PREFIX, vcType);

		List<ClientModel> vcClients = getClientModelsFromSession().stream()
				.filter(clientModel -> Optional.ofNullable(clientModel.getAttributes())
						.filter(attributes -> attributes.containsKey(prefixedType))
						.filter(attributes -> Arrays.asList(attributes.get(prefixedType).split(","))
								.contains(format.toString()))
						.isPresent())
				.collect(Collectors.toList());

		if (vcClients.isEmpty()) {
			LOGGER.infof("No SIOP-2-Client supporting type %s registered.", vcType);
			throw new ErrorResponseException(getErrorResponse(ErrorType.UNSUPPORTED_CREDENTIAL_TYPE));
		}
		return vcClients;
	}

	@NotNull
	private UserModel getUserFromSession(Optional<String> optionalToken) {
		LOGGER.debugf("Extract user form session. Realm in context is %s.", session.getContext().getRealm());
		// set the token in the context if its specifically provide. If empty, the authorization header will
		// automatically be evaluated
		optionalToken.ifPresent(bearerTokenAuthenticator::setTokenString);

		AuthenticationManager.AuthResult authResult = bearerTokenAuthenticator.authenticate();
		if (authResult == null) {
			throw new ErrorResponseException(getErrorResponse(ErrorType.INVALID_TOKEN));
		}
		UserModel userModel = authResult.getUser();
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
	private VCRequest getVCRequest(String vcType, UserModel userModel, List<ClientModel> clients, Set<Role> roles,
			Optional<Long> optionalMinExpiry) {
		// only include non-null & non-empty claims
		var claimsBuilder = VCClaims.builder();
		Optional.ofNullable(userModel.getEmail()).filter(email -> !email.isEmpty()).ifPresent(claimsBuilder::email);
		Optional.ofNullable(userModel.getFirstName()).filter(firstName -> !firstName.isEmpty())
				.ifPresent(claimsBuilder::firstName);
		Optional.ofNullable(userModel.getLastName()).filter(lastName -> !lastName.isEmpty())
				.ifPresent(claimsBuilder::familyName);
		Optional.ofNullable(roles).filter(rolesList -> !rolesList.isEmpty()).ifPresent(claimsBuilder::roles);
		getAdditionalClaims(clients).ifPresent(claimsBuilder::additionalClaims);
		VCClaims vcClaims = claimsBuilder.build();

		var vcConfigBuilder = VCConfig.builder();
		vcConfigBuilder.issuerDid(issuerDid)
				.proofType(LD_PROOF_TYPE);
		optionalMinExpiry
				.map(minExpiry -> Clock.systemUTC()
						.instant()
						.plus(Duration.of(minExpiry, ChronoUnit.MINUTES)))
				.map(FORMATTER::format)
				.ifPresent(vcConfigBuilder::expirationDate);
		VCConfig vcConfig = vcConfigBuilder.build();

		return VCRequest.builder().templateId(vcType)
				.config(vcConfig)
				.credentialData(VCData.builder()
						.credentialSubject(vcClaims)
						.build())
				.build();
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
				.flatMap(entry -> {

					String type = entry.getKey().replaceFirst(VC_TYPES_PREFIX, "");
					Set<FormatVO> supportedFormats = getFormatsFromString(entry.getValue());
					return supportedFormats.stream().map(formatVO -> {
								String id = buildIdFromType(formatVO, type);
								return new SupportedCredentialVO().id(id).types(List.of(type)).format(formatVO);
							}
					);
				}).collect(Collectors.toList());

	}

	@GET
	@Path(".well-known/openid-credential-issuer")
	@Produces({ "application/json" })
	@ApiOperation(value = "Return the issuer metadata", notes = "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-", tags = {})
	@ApiResponses(value = {
			@ApiResponse(code = 200, message = "The credentials issuer metadata", response = CredentialIssuerVO.class) })
	public Response getIssuerMetadata() {
		KeycloakContext currentContext = session.getContext();
		String realm = currentContext.getRealm().getId();
		String backendUrl = currentContext.getUri(UrlType.BACKEND).getBaseUri().toString();
		String issuer = String.format("%srealms/%s", backendUrl, realm);
		String issuerResourcePathPattern = "%srealms/%s/%s";
		String authorizationEndpointPattern = "%srealms/%s/.well-known/openid-configuration";
		String providerEndpoint = String.format(issuerResourcePathPattern, backendUrl, realm,
				VCIssuerRealmResourceProviderFactory.ID);
		return Response.ok().entity(new CredentialIssuerVO()
						.credentialIssuer(issuer)
						.authorizationServer(String.format(authorizationEndpointPattern, backendUrl, realm))
						.credentialEndpoint(providerEndpoint + "/" + CREDENTIAL_PATH)
						.credentialsSupported(getSupportedCredentials(currentContext)))
				.header("Access-Control-Allow-Origin", "*").build();
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
