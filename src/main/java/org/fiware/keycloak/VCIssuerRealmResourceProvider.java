package org.fiware.keycloak;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.fiware.keycloak.model.Role;
import org.fiware.keycloak.model.VCClaims;
import org.fiware.keycloak.model.VCConfig;
import org.fiware.keycloak.model.VCData;
import org.fiware.keycloak.model.VCRequest;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.validation.constraints.NotNull;
import javax.ws.rs.GET;
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
import java.util.stream.Collectors;

/**
 * Real-Resource to provide functionality for issuing VerfiableCredentials to users, depending on there roles in
 * registered SIOP-2 clients
 */
public class VCIssuerRealmResourceProvider implements RealmResourceProvider {

	private static final Logger LOGGER = Logger.getLogger(VCIssuerRealmResourceProvider.class);
	private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ISO_DATE_TIME
			.withZone(ZoneId.of(ZoneOffset.UTC.getId()));
	public static final String LD_PROOF_TYPE = "LD_PROOF";

	private final KeycloakSession session;
	private final String issuerDid;
	private final AppAuthManager.BearerTokenAuthenticator bearerTokenAuthenticator;
	private final WaltIdClient waltIdClient;

	public VCIssuerRealmResourceProvider(KeycloakSession session, String issuerDid, WaltIdClient waltIdClient,
			AppAuthManager.BearerTokenAuthenticator authenticator) {
		this.session = session;
		this.issuerDid = issuerDid;
		this.waltIdClient = waltIdClient;
		this.bearerTokenAuthenticator = authenticator;
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
				.map(attrs -> attrs.get(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES))
				.filter(Objects::nonNull)
				.flatMap(vcTypes -> Arrays.stream(vcTypes.split(",")))
				// collect to a set to remove duplicates
				.collect(Collectors.toSet()));

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
	public Response getVC(@QueryParam("type") String vcType, @QueryParam("token") String token) {
		LOGGER.debugf("Get a VC of type %s. Token parameter is %s.", vcType, token);

		UserModel userModel = getUserFromSession(Optional.ofNullable(token));

		List<ClientModel> clients = getClientsOfType(vcType);

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

		LOGGER.debugf("Respond with vc: %s", response);
		// the typical wallet will request with a CORS header and not accept responses without.
		return Response.ok().entity(response).header("Access-Control-Allow-Origin", "*").build();
	}

	@NotNull
	private List<ClientModel> getClientsOfType(String vcType) {
		LOGGER.debugf("Retrieve all clients of type %s", vcType);
		Optional.ofNullable(vcType).filter(type -> !type.isEmpty()).orElseThrow(() ->
				new ErrorResponseException("no_type_provided",
						"No VerifiableCredential-Type was provided in the request.",
						Response.Status.BAD_REQUEST));

		List<ClientModel> vcClients = getClientModelsFromSession().stream()
				.filter(clientModel -> Optional.ofNullable(clientModel.getAttributes())
						.map(attributes -> attributes.get(SIOP2ClientRegistrationProvider.SUPPORTED_VC_TYPES))
						.map(types -> types.contains(vcType))
						.orElse(false))
				.collect(Collectors.toList());

		if (vcClients.isEmpty()) {
			LOGGER.debugf("No SIOP-2-Client supporting type %s registered.", vcType);
			throw new ErrorResponseException("not_found",
					String.format("No SIOP-2-Client supporting the requested type %s is registered.", vcType),
					Response.Status.NOT_FOUND);
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
			throw new ErrorResponseException("unauthorized", "No user found in the session.",
					Response.Status.UNAUTHORIZED);
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
			return Optional.ofNullable(additionalClaims);
		}
	}

	@Getter
	@RequiredArgsConstructor
	private class ClientRoleModel {
		private final String clientId;
		private final List<RoleModel> roleModels;
	}
}
