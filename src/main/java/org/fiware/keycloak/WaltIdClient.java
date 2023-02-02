package org.fiware.keycloak;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.fiware.keycloak.model.DIDCreate;
import org.fiware.keycloak.model.VCRequest;
import org.jboss.logging.Logger;
import org.keycloak.services.ErrorResponseException;

import javax.validation.constraints.NotNull;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Optional;

/**
 * Client Implementation to connect with WaltId
 */
@RequiredArgsConstructor
public class WaltIdClient {

	private static final Logger LOGGER = Logger.getLogger(WaltIdClient.class);
	private static final String FAILED_VC_REQUEST_ERROR = "failed_vc_request";

	private static final String WALT_GET_DID_PATH = "%s:%s/v1/did/%s";
	private static final String WALT_CREATE_DID_PATH = "%s:%s/v1/did/create";
	private static final String WALT_ISSUE_VC_PATH = "%s:%s/v1/credentials/issue";

	private final String waltIdAddress;
	private final int waltIdCorePort;
	private final int waltIdSignatoryPort;
	private final ObjectMapper objectMapper;

	/**
	 * Return the VC according to the request object.
	 *
	 * @param vcRequest the VC request
	 * @return the VC
	 */
	@NotNull
	public String getVCFromWaltId(VCRequest vcRequest) {

		String jsonRepresentation = asJsonString(vcRequest);
		HttpResponse<String> response = null;
		try {
			response = HttpClient
					.newHttpClient()
					.send(
							HttpRequest.newBuilder()
									.POST(HttpRequest.BodyPublishers.ofString(
											jsonRepresentation))
									.uri(getSignatoryIssueURI())
									.build(), HttpResponse.BodyHandlers.ofString());
		} catch (IOException | InterruptedException e) {
			LOGGER.warn("Was not able to request walt.", e);
			Thread.currentThread().interrupt();
			throw new ErrorResponseException(FAILED_VC_REQUEST_ERROR, "Was not able to request a VC at walt-id.",
					Response.Status.BAD_GATEWAY);
		}
		if (response == null) {
			LOGGER.warn("Failed to get a response from walt-id.");
			throw new ErrorResponseException(FAILED_VC_REQUEST_ERROR, "Was not able to request a VC at walt-id.",
					Response.Status.INTERNAL_SERVER_ERROR);
		}
		if (response.statusCode() != Response.Status.OK.getStatusCode()) {
			LOGGER.warnf("Was not able to retrieve vc from walt-id. Response was %d: %s", response.statusCode(),
					response.body());
			throw new ErrorResponseException(FAILED_VC_REQUEST_ERROR, "Was not able to retrieve a VC at walt-id.",
					Response.Status.BAD_GATEWAY);
		}
		LOGGER.debugf("Response: %s - %s", response.headers().toString(), response.body());
		return response.body();
	}

	public Optional<String> getDidDocument(String did) {
		HttpResponse<String> response = null;
		try {
			response = HttpClient
					.newHttpClient()
					.send(
							HttpRequest.newBuilder()
									.GET()
									.uri(getCoreGetDidURI(did))
									.build(), HttpResponse.BodyHandlers.ofString());
		} catch (IOException | InterruptedException e) {
			throw new WaltIdConnectException("Was not able to request did from  walt-id.", e);
		}
		if (response == null || response.statusCode() != 200) {
			return Optional.empty();
		}
		return Optional.ofNullable(response.body());
	}

	public String createDid() {
		HttpResponse<String> response = null;
		try {
			response = HttpClient
					.newHttpClient()
					.send(
							HttpRequest.newBuilder()
									.POST(HttpRequest.BodyPublishers.ofString(
											asJsonString(new DIDCreate())))
									.uri(getCoreCreateDidURI())
									.build(), HttpResponse.BodyHandlers.ofString());
		} catch (IOException | InterruptedException e) {
			throw new WaltIdConnectException("Was not able to create did at walt-id.", e);
		}
		if (response == null || response.statusCode() != 200) {
			throw new WaltIdConnectException("Was not able to create did at walt-id.");
		}
		return response.body();
	}

	private URI getSignatoryIssueURI() {
		return URI.create(String.format(WALT_ISSUE_VC_PATH, waltIdAddress, waltIdSignatoryPort));
	}

	private URI getCoreGetDidURI(String did) {
		return URI.create(String.format(WALT_GET_DID_PATH, waltIdAddress, waltIdCorePort, did));
	}

	private URI getCoreCreateDidURI() {
		return URI.create(String.format(WALT_CREATE_DID_PATH, waltIdAddress, waltIdCorePort));
	}

	@NotNull
	private <T> String asJsonString(T javaObject) {
		try {
			return objectMapper.writeValueAsString(javaObject);
		} catch (JsonProcessingException e) {
			throw new ErrorResponseException("json_serialization_error", "Was not able to serialize object to json.",
					Response.Status.INTERNAL_SERVER_ERROR);
		}
	}
}
