package org.fiware.keycloak;

import com.google.auto.service.AutoService;
import org.jboss.logging.Logger;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.clientregistration.AbstractClientRegistrationProvider;
import org.keycloak.services.clientregistration.ClientRegistrationProviderFactory;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public class VCClientRegistrationProvider extends AbstractClientRegistrationProvider {

	private static final Logger LOGGER = Logger.getLogger(VCClientRegistrationProvider.class);

	public static final String SUPPORTED_VC_TYPES = "supportedVCTypes";
	public static final String EXPIRY_IN_MIN = "expiryInMin";
	public static final String VC_CLAIMS_PREFIX = "vc_";

	public VCClientRegistrationProvider(KeycloakSession session) {
		super(session);
	}

	@Override public void validateClient(ClientRepresentation clientRep, boolean create) {
		super.validateClient(clientRep, create);

	}

	@Override public void setEvent(EventBuilder event) {

		super.setEvent(event);
	}

	@Override public EventBuilder getEvent() {
		LOGGER.info("VC get event");

		return super.getEvent();
	}

	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response createVCClient(VCClient client) {

		ClientRepresentation clientRepresentation = toClientRepresentation(client);
		validate(clientRepresentation);

		ClientRepresentation cr = create(
				new VCClientRegistrationContext(session, clientRepresentation, this));
		URI uri = session.getContext().getUri().getAbsolutePathBuilder().path(cr.getClientId()).build();
		return Response.created(uri).entity(cr).build();
	}

	@PUT
	@Path("{clientId}")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response updateDefault(@PathParam("clientId") String clientDid, VCClient client) {
		client.setClientDid(clientDid);
		ClientRepresentation clientRepresentation = toClientRepresentation(client);
		validate(clientRepresentation);
		clientRepresentation = update(clientDid,
				new VCClientRegistrationContext(session, clientRepresentation, this));
		return Response.ok(clientRepresentation).build();
	}

	public static void validate(ClientRepresentation client) {
		String did = client.getClientId();
		if (did == null) {
			throw new ErrorResponseException("no_did", "A client did needs to be configured for VCClients",
					Response.Status.BAD_REQUEST);
		}
		if (!did.startsWith("did:")) {
			throw new ErrorResponseException("invalid_did", "The client did is not a valid did.",
					Response.Status.BAD_REQUEST);
		}
	}

	private ClientRepresentation toClientRepresentation(VCClient vcClient) {
		ClientRepresentation clientRepresentation = new ClientRepresentation();
		clientRepresentation.setProtocol(SIOP2LoginProtocolFactory.PROTOCOL_ID);
		clientRepresentation.setId(vcClient.getClientDid());
		clientRepresentation.setClientId(vcClient.getClientDid());

		Optional.ofNullable(vcClient.getDescription()).ifPresent(clientRepresentation::setDescription);
		Optional.ofNullable(vcClient.getName()).ifPresent(clientRepresentation::setName);
		Map<String, String> clientAttributes = new HashMap<>();

		// add potential additional claims
		clientAttributes.putAll(prefixClaims(vcClient.getAdditionalClaims()));

		Optional.ofNullable(vcClient.getExpiryInMin())
				.ifPresent(expiry -> clientAttributes.put(EXPIRY_IN_MIN, String.format("%s", expiry)));

		clientAttributes.put(SUPPORTED_VC_TYPES,
				Optional.ofNullable(vcClient.getSupportedVCTypes())
						.map(types -> String.format("VerifiableCredential,%s", types)).orElse("VerifiableCredential"));

		clientRepresentation.setAttributes(clientAttributes);
		LOGGER.infof("Generated client representation %s.", clientRepresentation);
		return clientRepresentation;
	}

	private Map<String, String> prefixClaims(Map<String, String> claimsToPrefix) {
		if (claimsToPrefix == null) {
			return Map.of();
		}

		return claimsToPrefix.entrySet()
				.stream()
				.collect(
						Collectors
								.toMap(e -> String.format("%s%s", VC_CLAIMS_PREFIX, e.getKey()),
										Map.Entry::getValue));
	}
}
