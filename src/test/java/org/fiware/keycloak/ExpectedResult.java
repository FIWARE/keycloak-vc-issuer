package org.fiware.keycloak;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import javax.crypto.spec.OAEPParameterSpec;
import java.util.Optional;

@Getter
@RequiredArgsConstructor
@AllArgsConstructor
public class ExpectedResult<T> {
	private final T expectedResult;
	private final String message;
	private Response response;

	@Getter
	@RequiredArgsConstructor
	public static class Response {
		private final int code;
		private final boolean success;

	}
}
