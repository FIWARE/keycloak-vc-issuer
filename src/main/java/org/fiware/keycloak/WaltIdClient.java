package org.fiware.keycloak;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.fiware.keycloak.model.DIDCreate;
import org.fiware.keycloak.model.DIDKey;
import org.fiware.keycloak.model.KeyId;
import org.fiware.keycloak.model.VCRequest;
import org.jboss.logging.Logger;
import org.keycloak.services.ErrorResponseException;

import javax.validation.constraints.NotNull;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.ServerErrorException;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Optional;

/**
 * Client Implementation to connect with WaltId
 */
@RequiredArgsConstructor
public class WaltIdClient {

	private static final Logger LOGGER = Logger.getLogger(WaltIdClient.class);
	private static final String FAILED_VC_REQUEST_ERROR = "failed_vc_request";

	private static final String WALT_GET_DID_PATH = "%s:%s/v1/did/%s";
	private static final String WALT_GET_DID_LIST_PATH = "%s:%s/v1/did";
	private static final String WALT_CREATE_DID_PATH = "%s:%s/v1/did/create";
	private static final String WALT_IMPORT_KEY_PATH = "%s:%s/v1/key/import";
	private static final String WALT_IMPORT_DID_PATH = "%s:%s/v1/did/import?keyId=%s";
	private static final String WALT_ISSUE_VC_PATH = "%s:%s/v1/credentials/issue";

	@Getter
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
		LOGGER.debugf("Requesting %s", jsonRepresentation);
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
			throw new ServerErrorException("Was not able to request a VC at walt-id.", Response.Status.BAD_GATEWAY);
		}
		if (response == null) {
			LOGGER.warn("Failed to get a response from walt-id.");
			throw new InternalServerErrorException("Was not able to request a VC at walt-id.");
		}
		if (response.statusCode() != Response.Status.OK.getStatusCode()) {
			LOGGER.warnf("Was not able to retrieve vc from walt-id. Response was %d: %s", response.statusCode(),
					response.body());
			throw new ServerErrorException("Was not able to retrieve a VC at walt-id.", Response.Status.BAD_GATEWAY);
		}
		LOGGER.debugf("Response: %s - %s", response.headers().toString(), response.body());
		return response.body();
	}

	public List<String> getDids() {
		HttpResponse<String> response = null;
		try {
			response = HttpClient
					.newHttpClient()
					.send(
							HttpRequest.newBuilder()
									.GET()
									.uri(getCoreGetDidListURI())
									.build(), HttpResponse.BodyHandlers.ofString());
		} catch (IOException | InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new WaltIdConnectException("Was not able to request did list from  walt-id.", e);
		}
		if (response == null || response.statusCode() != 200) {
			return List.of();
		}
		try {
			return objectMapper.readValue(response.body(), List.class);
		} catch (JsonProcessingException e) {
			LOGGER.warnf("Did not receive a valid did list(was %s), we assume its empty.", response.body(), e);
			return List.of();
		}
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
			Thread.currentThread().interrupt();
			throw new WaltIdConnectException("Was not able to request did from  walt-id.", e);
		}
		if (response == null || response.statusCode() != 200) {
			return Optional.empty();
		}
		return Optional.ofNullable(response.body());
	}

	public String createDid() {
		LOGGER.info("Create a new did.");
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
			Thread.currentThread().interrupt();
			throw new WaltIdConnectException("Was not able to create did at walt-id.", e);
		}
		if (response == null || response.statusCode() != 200) {
			throw new WaltIdConnectException("Was not able to create did at walt-id.");
		}
		return response.body();
	}

	public void importDid(String did, String key) {
		HttpResponse<String> response = null;
		try {
			response = HttpClient
					.newHttpClient()
					.send(
							HttpRequest.newBuilder()
									.POST(HttpRequest.BodyPublishers.ofString(did))
									.uri(getCoreImportDidURI(key))
									.build(), HttpResponse.BodyHandlers.ofString());
		} catch (IOException | InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new WaltIdConnectException("Was not able to import did at walt-id.", e);
		}
		if (response == null || response.statusCode() != 201) {
			throw new WaltIdConnectException("Was not able to import did at walt-id.");
		}
		LOGGER.infof("Successfully imported did %s with key %s. Response was: %s", did, key, response.body());
	}

	public String importDIDKey(DIDKey didKey) {
		HttpResponse<String> response = null;
		try {
			response = HttpClient
					.newHttpClient()
					.send(
							HttpRequest.newBuilder()
									.POST(HttpRequest.BodyPublishers.ofString(
											asJsonString(didKey)))
									.uri(getCoreImportKeyURI())
									.build(), HttpResponse.BodyHandlers.ofString());
		} catch (IOException | InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new WaltIdConnectException("Was not able to import the key at walt-id.", e);
		}
		if (response == null || response.statusCode() != 200) {
			Optional.ofNullable(response).ifPresent(
					r -> LOGGER.warnf("Received error response %s: %s", r.statusCode(), r.body()));
			throw new WaltIdConnectException("Was not able to import the key at walt-id.");
		}
		try {
			return objectMapper.readValue(response.body(), KeyId.class).getId();
		} catch (JsonProcessingException e) {
			LOGGER.warnf("Received an invalid key-id response: %s.", response.body());
			throw new WaltIdConnectException("Was not able to retrieve a valid key-id response.", e);
		}
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

	private URI getCoreImportDidURI(String keyId) {
		return URI.create(String.format(WALT_IMPORT_DID_PATH, waltIdAddress, waltIdCorePort, keyId));
	}

	private URI getCoreImportKeyURI() {
		return URI.create(String.format(WALT_IMPORT_KEY_PATH, waltIdAddress, waltIdCorePort));
	}

	private URI getCoreGetDidListURI() {
		return URI.create(String.format(WALT_GET_DID_LIST_PATH, waltIdAddress, waltIdCorePort));
	}

	@NotNull
	private <T> String asJsonString(T javaObject) {
		try {
			return objectMapper.writeValueAsString(javaObject);
		} catch (JsonProcessingException e) {
			LOGGER.errorf("Was not able to serialize. %s", e.getMessage());
			throw new InternalServerErrorException("Was not able to serialize object to json.");
		}
	}
}
