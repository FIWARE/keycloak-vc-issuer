package org.fiware.keycloak;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class ExpectedResult<T> {
	private final T expectedResult;
	private final String message;
}
