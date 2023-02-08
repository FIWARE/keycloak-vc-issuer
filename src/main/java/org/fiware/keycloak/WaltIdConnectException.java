package org.fiware.keycloak;

public class WaltIdConnectException extends RuntimeException {
	public WaltIdConnectException(String message) {
		super(message);
	}

	public WaltIdConnectException(String message, Throwable cause) {
		super(message, cause);
	}
}
