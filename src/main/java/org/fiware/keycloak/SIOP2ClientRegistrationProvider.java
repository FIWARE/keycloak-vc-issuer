package org.fiware.keycloak;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.clientregistration.AbstractClientRegistrationProvider;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Provides the client-registration functionality for siop2-clients.
 */
public class SIOP2ClientRegistrationProvider extends AbstractClientRegistrationProvider {

	private static final Logger LOGGER = Logger.getLogger(SIOP2ClientRegistrationProvider.class);

	public static final String EXPIRY_IN_MIN = "expiryInMin";
	public static final String VC_CLAIMS_PREFIX = "vc_";
	public static final String VC_TYPES_PREFIX = "vctypes_";

	public SIOP2ClientRegistrationProvider(KeycloakSession session) {
		super(session);
	}

	// CUD implementations for the SIOP-2 client

	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response createSIOP2Client(SIOP2Client client) {

		ClientRepresentation clientRepresentation = toClientRepresentation(client);
		validate(clientRepresentation);

		ClientRepresentation cr = create(
				new SIOP2ClientRegistrationContext(session, clientRepresentation, this));
		URI uri = session.getContext().getUri().getAbsolutePathBuilder().path(cr.getClientId()).build();
		return Response.created(uri).entity(cr).build();
	}

	@PUT
	@Path("{clientId}")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response updateSIOP2Client(@PathParam("clientId") String clientDid, SIOP2Client client) {
		client.setClientDid(clientDid);
		ClientRepresentation clientRepresentation = toClientRepresentation(client);
		validate(clientRepresentation);
		clientRepresentation = update(clientDid,
				new SIOP2ClientRegistrationContext(session, clientRepresentation, this));
		return Response.ok(clientRepresentation).build();
	}

	@DELETE
	@Path("{clientId}")
	public Response deleteSIOP2Client(@PathParam("clientId") String clientDid) {
		delete(clientDid);
		return Response.noContent().build();
	}

	/**
	 * Validates the clientrepresentation to fulfill the requirement of a SIOP-2 client
	 *
	 * @param client
	 */
	public static void validate(ClientRepresentation client) {
		String did = client.getClientId();
		if (did == null) {
			throw new ErrorResponseException("no_did", "A client did needs to be configured for SIOP-2 clients",
					Response.Status.BAD_REQUEST);
		}
		if (!did.startsWith("did:")) {
			// TODO: future implementations should check the actual validity of a did, instead of just the format
			throw new ErrorResponseException("invalid_did", "The client did is not a valid did.",
					Response.Status.BAD_REQUEST);
		}
	}

	/**
	 * Translate an incoming {@link SIOP2Client} into a keycloak native {@link ClientRepresentation}.
	 *
	 * @param siop2Client pojo, containing the SIOP-2 client parameters
	 * @return a clientrepresentation, fitting keycloaks internal model
	 */
	protected static ClientRepresentation toClientRepresentation(SIOP2Client siop2Client) {
		ClientRepresentation clientRepresentation = new ClientRepresentation();
		// protocol needs to be SIOP-2
		clientRepresentation.setProtocol(SIOP2LoginProtocolFactory.PROTOCOL_ID);
		// id and clientId cannot be equal since did's might be to long, already validated to be non-null
		clientRepresentation.setId(UUID.randomUUID().toString());
		clientRepresentation.setClientId(siop2Client.getClientDid());
		// only add non-null parameters
		Optional.ofNullable(siop2Client.getDescription()).ifPresent(clientRepresentation::setDescription);
		Optional.ofNullable(siop2Client.getName()).ifPresent(clientRepresentation::setName);

		// add potential additional claims
		Map<String, String> clientAttributes = new HashMap<>(
				prefixClaims(VC_CLAIMS_PREFIX, siop2Client.getAdditionalClaims()));

		// only set expiry if present
		Optional.ofNullable(siop2Client.getExpiryInMin())
				.ifPresent(expiry -> clientAttributes.put(EXPIRY_IN_MIN, String.format("%s", expiry)));
		// only set supported VCs if present
		if (siop2Client.getSupportedVCTypes() != null) {
			siop2Client.getSupportedVCTypes()
					.forEach(supportedCredential -> {
						String typeKey = String.format("%s%s", VC_TYPES_PREFIX, supportedCredential.getType());
						if (clientAttributes.containsKey(typeKey)) {
							clientAttributes.put(typeKey, String.format("%s,%s",
									clientAttributes.get(typeKey),
									supportedCredential.getFormat().toString()));
						} else {
							clientAttributes.put(typeKey,
									supportedCredential.getFormat().toString());
						}
					});
		}
		if (!clientAttributes.isEmpty()) {
			clientRepresentation.setAttributes(clientAttributes);
		}

		LOGGER.debugf("Generated client representation {}.", clientRepresentation);
		return clientRepresentation;
	}

	/**
	 * Prefix the map of claims, to differentiate them from potential internal once. Only the prefixed claims will be
	 * used for creating VCs.
	 */
	private static Map<String, String> prefixClaims(String prefix, Map<String, String> claimsToPrefix) {
		if (claimsToPrefix == null) {
			return Map.of();
		}
		return claimsToPrefix.entrySet()
				.stream()
				.collect(
						Collectors
								.toMap(e -> String.format("%s%s", prefix, e.getKey()),
										Map.Entry::getValue));
	}
}
