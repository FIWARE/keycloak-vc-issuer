package org.fiware.keycloak;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
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

/**
 * Client Implementation to connect with WaltId
 */
@RequiredArgsConstructor
public class WaltIdClient {

	private static final Logger LOGGER = Logger.getLogger(WaltIdClient.class);
	private static final String FAILED_VC_REQUEST_ERROR = "failed_vc_request";
	private final URI waltIdAddress;
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
									.uri(waltIdAddress)
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
			LOGGER.warnf("Was not able to retrieve vc from walt-id. Response was %s: %s", response.statusCode(),
					response.body());
			throw new ErrorResponseException(FAILED_VC_REQUEST_ERROR, "Was not able to request a VC at walt-id.",
					Response.Status.BAD_GATEWAY);
		}
		return response.body();
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
