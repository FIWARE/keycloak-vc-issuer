package org.fiware.keycloak;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import com.google.zxing.qrcode.encoder.ByteMatrix;
import com.google.zxing.qrcode.encoder.Encoder;
import com.google.zxing.qrcode.encoder.QRCode;
import liquibase.pro.packaged.G;
import org.apache.http.HttpStatus;
import org.fiware.keycloak.model.Role;
import org.fiware.keycloak.model.VCClaims;
import org.fiware.keycloak.model.VCConfig;
import org.fiware.keycloak.model.VCData;
import org.fiware.keycloak.model.VCRequest;
import org.jboss.logging.Logger;
import org.jetbrains.annotations.NotNull;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RoleModel;
import org.keycloak.models.TokenManager;
import org.keycloak.models.UserModel;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
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
import java.util.stream.Collectors;

public class VCIssuerRealmResourceProvider implements RealmResourceProvider {

	private static final Logger LOGGER = Logger.getLogger(VCIssuerRealmResourceProvider.class);
	private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ISO_DATE_TIME
			.withZone(ZoneId.of(ZoneOffset.UTC.getId()));

	private final KeycloakSession session;
	private final String issuerDid;
	private final String waltidAddress;
	private final ObjectMapper objectMapper;

	public VCIssuerRealmResourceProvider(KeycloakSession session, String issuerDid, String waltidAddress,
			ObjectMapper objectMapper) {
		this.session = session;
		this.issuerDid = issuerDid;
		this.waltidAddress = waltidAddress;
		this.objectMapper = objectMapper;
	}

	@Override
	public Object getResource() {
		return this;
	}

	@Override
	public void close() {
	}

	@GET
	@Path("types")
	@Produces(MediaType.APPLICATION_JSON)
	public Response getTypes() {
		AppAuthManager.BearerTokenAuthenticator bearerTokenAuthenticator = new AppAuthManager.BearerTokenAuthenticator(
				session);
		LOGGER.debugf("Context %s", session.getContext().getRealm());
		AuthenticationManager.AuthResult authResult = bearerTokenAuthenticator.authenticate();
		if (authResult == null) {
			return Response.status(Response.Status.UNAUTHORIZED).build();
		}
		UserModel userModel = authResult.getUser();
		LOGGER.infof("User is %s", userModel.getId());

		List<String> supportedTypes = List.copyOf(getClientModelsFromSession().stream()
				.peek(clientModel -> LOGGER.infof("The client %s", clientModel.getClientId()))
				.map(ClientModel::getAttributes)
				.filter(Objects::nonNull)
				.peek(attrs -> LOGGER.infof("The attrs %s", attrs))
				.map(attrs -> attrs.get(VCClientRegistrationProvider.SUPPORTED_VC_TYPES))
				.filter(Objects::nonNull)
				.flatMap(vcTypes -> Arrays.stream(vcTypes.split(",")))
				.peek(type -> LOGGER.infof("The type %s", type))
				// to set removes duplicates
				.collect(Collectors.toSet()));
		return Response.status(200).entity(supportedTypes).build();
	}

	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Response getVC(@QueryParam("type") String vcType, @QueryParam("token") String token) {
		LOGGER.infof("Get %s", token);

		if (vcType == null || vcType.isEmpty()) {
			return Response.status(Response.Status.BAD_REQUEST).build();
		}

		AppAuthManager.BearerTokenAuthenticator bearerTokenAuthenticator = new AppAuthManager.BearerTokenAuthenticator(
				session);

		LOGGER.infof("Context %s", session.getContext().getRealm());
		if(token != null && !token.isEmpty()) {
			bearerTokenAuthenticator.setTokenString(token);
		} else {
			//if no token is provided, the one from the auth-header will be taken.
		}
		AuthenticationManager.AuthResult authResult = bearerTokenAuthenticator.authenticate();
		if (authResult == null) {
			return Response.status(Response.Status.UNAUTHORIZED).build();
		}
		UserModel userModel = authResult.getUser();
		LOGGER.infof("User is %s", userModel.getId());

		List<ClientModel> vcClients = getClientModelsFromSession().stream()
				.filter(clientModel -> clientModel.getAttributes().get(VCClientRegistrationProvider.SUPPORTED_VC_TYPES)
						.contains(vcType))
				.collect(Collectors.toList());

		Optional<Long> optionalMinExpiry = vcClients.stream()
				.map(clientModel -> clientModel.getAttributes().get(VCClientRegistrationProvider.EXPIRY_IN_MIN))
				.filter(Objects::nonNull)
				.map(Long::parseLong)
				.sorted()
				.findFirst();

		if (vcClients.isEmpty()) {
			LOGGER.infof("No VCClients supporting type %s registered.", vcType);
			return Response.status(404).build();
		}

		List<Role> roles = vcClients.stream().map(this::toRolesClaim).collect(Collectors.toList());

		VCClaims vcClaims = VCClaims.builder()
				.email(userModel.getEmail())
				.familyName(userModel.getLastName())
				.firstName(userModel.getFirstName())
				.roles(roles)
				.build();

		vcClaims.setAdditionalClaims(vcClients.stream()
				.flatMap(clientModel -> clientModel.getAttributes().entrySet().stream())
				// only include the claims explicitly intended for vc
				.filter(entry -> entry.getKey().startsWith(VCClientRegistrationProvider.VC_CLAIMS_PREFIX))
				.collect(
						Collectors.toMap(
								// remove the prefix before sending it
								e -> e.getKey().replaceFirst(VCClientRegistrationProvider.VC_CLAIMS_PREFIX, ""),
								// value is taken untouched if its unique
								Map.Entry::getValue,
								// if multiple values for the same key exist, we add them comma separated.
								// this needs to be improved, once more requirements are known.
								(e1, e2) -> {
									if (e1.equals(e2) || e1.contains(e2)) {
										return e1;
									} else {
										return String.format("%s,%s", e1, e2);
									}
								}
						)));

		VCConfig vcConfig = VCConfig.builder()
				.issuerDid(issuerDid)
				// TODO: check if it needs to be configurable
				.proofType("LD_PROOF")
				.build();
		optionalMinExpiry
				.map(minExpiry -> Clock.systemUTC()
						.instant()
						.plus(Duration.of(minExpiry, ChronoUnit.MINUTES)))
				.map(FORMATTER::format)
				.ifPresent(vcConfig::setExpirationDate);
		VCRequest vcRequest = VCRequest.builder().templateId(vcType)
				.config(vcConfig)
				.credentialData(VCData.builder()
						.credentialSubject(vcClaims)
						.build())
				.build();
		try {
			HttpResponse<String> response = HttpClient.newHttpClient()
					.send(
							HttpRequest.newBuilder()
									.POST(HttpRequest.BodyPublishers.ofString(
											objectMapper.writeValueAsString(vcRequest)))
									.uri(URI.create(waltidAddress))
									.build(), HttpResponse.BodyHandlers.ofString());
			return Response.ok(response.body()).build();
		} catch (IOException | InterruptedException e) {
			LOGGER.error("Was not able to request walt.", e);
			return Response.status(Response.Status.BAD_GATEWAY).build();
		}
	}

	@NotNull
	private List<ClientModel> getClientModelsFromSession() {
		return session.clients().getClientsStream(session.getContext().getRealm())
				.filter(clientModel -> clientModel.getProtocol() != null)
				.filter(clientModel -> clientModel.getProtocol().equals(SIOP2LoginProtocolFactory.PROTOCOL_ID))
				.collect(Collectors.toList());
	}

	private Role toRolesClaim(ClientModel cm) {
		List<String> roleNames = cm.getRolesStream().map(RoleModel::getName).collect(Collectors.toList());
		return Role.builder().names(roleNames).target(cm.getClientId()).build();
	}
}
