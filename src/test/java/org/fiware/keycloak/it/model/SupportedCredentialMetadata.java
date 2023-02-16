package org.fiware.keycloak.it.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@EqualsAndHashCode
@Getter
@ToString
@JsonIgnoreProperties(ignoreUnknown = true)
public class SupportedCredentialMetadata {

	public String format;
	public String id;
	public Set<String> types;
}
