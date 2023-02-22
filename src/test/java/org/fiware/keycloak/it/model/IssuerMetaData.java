package org.fiware.keycloak.it.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.net.URL;
import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@EqualsAndHashCode
@Getter
@ToString
@JsonIgnoreProperties(ignoreUnknown = true)
public class IssuerMetaData {

	@JsonProperty("credential_issuer")
	public URL credentialIssuer;
	@JsonProperty("authorization_server")
	public URL authorizationServer;
	@JsonProperty("credential_endpoint")
	public URL credentialEndpoint;

	@JsonProperty("credentials_supported")
	public Set<SupportedCredentialMetadata> credentialsSupported;

}
