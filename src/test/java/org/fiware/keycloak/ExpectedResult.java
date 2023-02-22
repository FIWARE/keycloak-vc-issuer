package org.fiware.keycloak;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import org.junit.jupiter.api.Tag;

import javax.crypto.spec.OAEPParameterSpec;
import java.util.Optional;

@Getter
@RequiredArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class ExpectedResult<T> {
	private final T expectedResult;
	private final String message;
	private Response response;

	@Getter
	@RequiredArgsConstructor
	@EqualsAndHashCode
	@ToString
	public static class Response {
		private final int code;
		private final boolean success;

	}
}
