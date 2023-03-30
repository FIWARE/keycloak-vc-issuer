# Keycloak VC-Issuer

[![FIWARE Security](https://nexus.lab.fiware.org/repository/raw/public/badges/chapters/security.svg)](https://www.fiware.org/developers/catalogue/)
[![License badge](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Container Repository on Quay](https://img.shields.io/badge/quay.io-VCIssuer-green "Container Repository on Quay")](https://quay.io/repository/fiware/keycloak-vc-issuer)
[![Integration-Test](https://github.com/FIWARE/keycloak-vc-issuer/actions/workflows/integration-test.yaml/badge.svg)](https://github.com/FIWARE/keycloak-vc-issuer/actions/workflows/integration-test.yaml)
[![Unit-Test](https://github.com/FIWARE/keycloak-vc-issuer/actions/workflows/test.yaml/badge.svg)](https://github.com/FIWARE/keycloak-vc-issuer/actions/workflows/test.yaml)

A plugin for [Keycloak](https://www.keycloak.org/) to
issue [VerifiableCredentials](https://www.w3.org/TR/vc-data-model/).

## Compatibility

The plugin is developed with the [20.0.3 libraries](https://github.com/keycloak/keycloak/tree/20.0.3) and tested against
all Keycloak Minor-Releases >=18.0.0. Please check the [Compatibility-Matrix](./doc/compatibility/compatibility.md) for
more information. The matrix gets updated every night.

## OpenID for Verifiable Credential Issuance 

The plugin targets compliance with the [OpenID for Verifiable Credential Issuance(OIDC4VCI)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) standard, 
in order to be compatible with Wallets complying with the [European Digital Identity Wallet Architecture and Reference Framework](https://digital-strategy.ec.europa.eu/en/library/european-digital-identity-wallet-architecture-and-reference-framework) and
any other standard-conformant Wallet-implementation. It currently supports the following parts of the spec:

- [3.5 Pre-Authorized Code Flow](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-pre-authorized-code-flow):
  - in order to securely issue credentials, the plugin can offer pre-authorized authorization codes to authenticated users
  - the code is connected to the user-session that requested the [Credential Offer](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer)
  - the code can be exchanged for an access-token through a token-endpoint as described in [RFC 6749](https://www.rfc-editor.org/info/rfc6749)
- [4. Credential Offer Endpoint](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint):
  - to initiate standard conformant issuance, an endpoint to retrieve [Credential Offer](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer) is provided
  - the endpoint is available at ```/realms/{realm-id}/verifiable-credential/{issuer-did}/credential-offer``` and accepts the type and format to be offered
  - see [api-spec](./api/api.yaml) for more
- [6. Token Endpoint](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-endpoint)
  - supports token exchange through the pre-authorized flow
  - available per issuer at ```/realms/{realm-id}/verifiable-credential/{issuer-did}/token```
  - see [api-spec](./api/api.yaml) for more
  - pin-check is currently not supported
- [7. Credential Endpoint](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-endpoint)
  - provides a valid credential, according to the requested type and format
  - currently supports jwt_vc_json, jwt_vc_json-ld, ldp_vc and for backward-compatibility jwt_vc(which defaults to jwt_vc_json)
  - proof-checking for the request is only supported for proof-type jwt(yet)
- [10.2. Credential Issuer Metadata](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata)
  - provides the metadata for the issuer

## Functionality

The VC-Issuer plugin provides an integration for [VerifiableCredentials](https://www.w3.org/TR/vc-data-model/)
into [Keycloak](https://www.keycloak.org/). It allows to manage potential receivers of VerifiableCredentials
as [SIOP-2 Clients](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html), allowing to manage users and roles
in the well-known Keycloak way. In addition to that, it provides the endpoints for (authenticated) users to receive
VerifiableCredentials for their account. To integrate with the Account-Console frontend, a theme(```siop-2```) is
included.

### OpenID for Verifiable Credential Issuance

The plugin targets compliance with
the [OpenID for Verifiable Credential Issuance(OIDC4VCI)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
standard, in order to be compatible with Wallets complying with
the [European Digital Identity Wallet Architecture and Reference Framework](https://digital-strategy.ec.europa.eu/en/library/european-digital-identity-wallet-architecture-and-reference-framework)
and any other standard-conformant Wallet-implementation. It currently supports the following parts of the spec:

- [3.5 Pre-Authorized Code Flow](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-pre-authorized-code-flow):
    - in order to securely issue credentials, the plugin can offer pre-authorized authorization codes to authenticated
      users
    - the code is connected to the user-session that requested
      the [Credential Offer](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer)
    - the code can be exchanged for an access-token through a token-endpoint as described
      in [RFC 6749](https://www.rfc-editor.org/info/rfc6749)
- [4. Credential Offer Endpoint](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint):
    - to initiate standard conformant issuance, an endpoint to
      retrieve [Credential Offer](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer)
      is provided
    - the endpoint is available at ```/realms/{realm-id}/verifiable-credential/{issuer-did}/credential-offer``` and
      accepts the type and format to be offered
    - see [api-spec](./api/api.yaml) for more
- [6. Token Endpoint](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-endpoint)
    - supports token exchange through the pre-authorized flow
    - available per issuer at ```/realms/{realm-id}/verifiable-credential/{issuer-did}/token```
    - see [api-spec](./api/api.yaml) for more
    - pin-check is currently not supported
- [7. Credential Endpoint](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-endpoint)
    - provides a valid credential, according to the requested type and format
    - currently supports jwt_vc_json, jwt_vc_json-ld, ldp_vc and for backward-compatibility jwt_vc(which defaults to
      jwt_vc_json)
    - does not support binding to the enduser(e.g. via proof-parameter), yet
- [10.2. Credential Issuer Metadata](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata)
    - provides the metadata for the issuer

## Dependencies & Configuration

In order to provide the capabilities of issuing VerifiableCredentials and handling DIDs, Keycloak relies
on [Walt-ID](https://github.com/walt-id/waltid-ssikit) as a downstream component.
The [integration-test setup](src/test/k3s) provides an example on how to run and integrate it. The configuration is
provided via environment variables:

|Name| Description                                                                          | Default    |
|----|--------------------------------------------------------------------------------------|------------|
|VCISSUER_WALTID_ADDRESS| Base address of walt-id. Has to include the protocol.                                ||
|VCISSUER_WALTID_CORE_PORT| Port to be used for connecting the walt-id's core-api.                               | ```7000``` |
|VCISSUER_WALTID_SIGNATORY_PORT| Port to be used for connecting the walt-id's signatory-api.                          | ```7001``` |
|VCISSUER_ISSUER_DID| DID to be used for issuing credentials. If none is provided, Keycloak will create one. | |
|VCISSUER_ISSUER_KEY_FILE| Path to the file containing the issuer key.                                          | |

## Usage

### Api

The plugin provides multiple endpoints through its API ([see OpenApi-Doc](./doc/api.yaml)) as a realm resource. They
seperate into two categories. See the [see OpenApi-Doc](./doc/api.yaml) for detailed information and examples:

- [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
  compatible endpoints - tag ```OIDC4VCI```
- convenience endpoints to allow a more comfortable frontend integration - tag ```IssuerPlugin```

Most endpoints are only available to authenticated users, the following three informatory endpoints are publicly
available:

- /{issuerDid}/.well-known/openid-credential-issuer - provides the issuer metadata in an OIDC4VCI compliant way
- /{issuerDid}/.well-known/openid-configuration - provides the openid-configuration in an OIDC4VCI compliant(and
  therefor als [RFC8414](https://www.rfc-editor.org/info/rfc8414) compliant) way
- /issuer - provides just the did of the configured issuer, that can be used to construct the other paths. Provided to
  ease frontend integrations

### Protocol

The provider does support the protocol-type ```SIOP-2```, therefore such clients can be created and managed. Since
integration into the Admin-Console is still open, the clients need to be created through the api. A registration will
look like:

```json
{
  "clientId": "did:key:z6Mkv4Lh9zBTPLoFhLHHMFJA7YAeVw5HFYZV8rkdfY9fNtm3",
  "enabled": true,
  "description": "Client to receive Verifiable Credentials.",
  "protocol": "SIOP-2",
  "supportedVCTypes": [
    {
      "type": "PacketDeliveryService",
      "format": "ldp_vc"
    },
    {
      "type": "PacketDeliveryService",
      "format": "jwt_vc_json"
    }
  ]
}
```

Alternatively, the client can also be directly create through the clients api(for example when using declarative
configuration via [keycloak-config-cli](https://github.com/adorsys/keycloak-config-cli), find an
example [here](https://github.com/FIWARE-Ops/batterypass-demonstrator/tree/main/applications/keycloak-one)):

```json
 {
  "clientId": "did:key:z6MkigCEnopwujz8Ten2dzq91nvMjqbKQYcifuZhqBsEkH7g",
  "enabled": true,
  "description": "Client to receive Verifiable Credentials",
  "surrogateAuthRequired": false,
  "alwaysDisplayInConsole": false,
  "clientAuthenticatorType": "client-secret",
  "defaultRoles": [],
  "redirectUris": [],
  "webOrigins": [],
  "notBefore": 0,
  "bearerOnly": false,
  "consentRequired": false,
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "serviceAccountsEnabled": false,
  "publicClient": false,
  "frontchannelLogout": false,
  "protocol": "SIOP-2",
  "attributes": {
    "expiryInMin": "3600",
    // attributes are of type "string": "string", thus we provide the prefixed-type, together with a comma-seperated list of formats 
    "vctypes_BatteryPassAuthCredential": "ldp_vc,jwt_vc_json"
  },
  "authenticationFlowBindingOverrides": {},
  "fullScopeAllowed": true,
  "nodeReRegistrationTimeout": -1,
  "defaultClientScopes": [],
  "optionalClientScopes": []
}
```

Once the client is created, roles and role-assignemnts can be managed the same way as for every other type, through the
API or the Admin-Console.

## Demo

In order to issue credentials, first a SIOP-2 client has to be created. Integration in the admin-console is still open,
thus has to be done through the api:

```shell
url --location --request POST '<KEYCLOAK_HOST>/realms/master/clients-registrations/SIOP-2' \
--header 'Authorization: Bearer <TOKEN>' \
--header 'Content-Type: application/json' \
--data-raw '{
    // did of the client
    "clientDid": "did:key:z6MkmxVQztpb1JpAEgfJaqFN5g7CcJFPSMsJ1S6PiBjxR7Vxp",
    // type of the supported credentials
    "supportedVCTypes": [
        {
          "type": "PacketDeliveryService",
          "format": "ldp_vc"
        },
        {
          "type": "PacketDeliveryService",
          "format": "jwt_vc_json"
        }
    ],
    // 'traditional' description
    "description": "Client to receive Verifiable Credentials.",
    // max lifetime of the VC
    "expiryInMin": 3600,
    // additionalClaims to be added to the VC
    "additionalClaims": {
        "a":"b",
        "c":"d"
    }
}'
```

Client in the console:

![admin-console](doc/admin-console.png)

Once the client is created, it is available in the admin-console. Through the standard interfaces, client-roles can be
created and assigned to users. Once that is done, a logged in user can use the account-interface to get Verifiable
Credentials:

Account-Console overview:

![account-console](doc/account.png)

Get a VC:

![get-vc](doc/vc.png)

The frontend currently supports three types of QR-Codes:

- "Request VerifiableCredential" - will provide the credential of the requested type directly as json
- "Generate VerifiableCredential-Request" - will provide a request to be used for retrieving the credential, can f.e. be
  used with the [demo-wallet](https://github.com/hesusruiz/VCWallet)
- "Initiate Credential-Issuance(OIDC4VCI)" - will provide a URI-formatted, OIDC4VCI compatible credential-offer, that
  can be used by compliant wallets.

## Deployment

The VC Issuer is a fully-self-contained provider, thus the jar-file only has to be added to the ```providers```-folder
of Keycloak(typically under ```/opt/keycloak/providers```). Keycloak will automatically pick-up the provider at
start-time. The plugin is available as jar-file
through [the github-releases](https://github.com/wistefan/keycloak-vc-issuer/releases) or as
a [container at quay.io](https://quay.io/repository/fiware/keycloak-vc-issuer). The container can for example be used as
an init-container, to copy the jar file into a shared folder and make it available for Keycloak. See
the [k3s-setup](./src/test/k3s)
or [this one](https://github.com/FIWARE-Ops/batterypass-demonstrator/tree/main/applications/keycloak-one) as examples.

To have the account-console integration, the ```SIOP-2```-theme has to be enabled for the realm:

![setup-theme](doc/siop-theme.png)

In addition to Keycloak, an installation of [WaltID-SSIKit](https://github.com/walt-id/waltid-ssikit) needs to be
provided. Keycloak uses it, to create the actual credentials. It can f.e. be deployed
via [Helm-Chart](https://github.com/i4Trust/helm-charts/tree/main/charts/vcwaltid).

## Testing

### Unit-Testing

The unit-tests are located at [src/test/java](./src/test/java) and are postfixed with ```Test```. The tests
use [Junit5](https://junit.org/junit5/docs/current/user-guide/)
and [Mockito](https://site.mockito.org/) and will cover the essential logic inside the plugin.

### Integration-Testing

Since the plugin has to work as part of [Keycloak]((https://www.keycloak.org/)) and does
use [WaltId](https://docs.walt.id/v/ssikit/ssi-kit/readme)
as a downstream dependency, integration-test are essential. The tests use a [k3s](https://k3s.io/) setup, integrated
through the [k3s-maven-plugin](https://github.com/kokuwaio/k3s-maven-plugin), which provides a preconfigured Keycloak
and WaltId environment. The manifests can be found at [src/test/k3s](./src/test/k3s). The test implementations are
postfixed with ```IntegrationTest```. To run the full integration test suite, use the maven
profile ```integration-test```:

```shell
mvn clean install -Pintegration-test
```

This will automatically build and deploy the current development, bind selected services to localhost and run all
integration-tests. To support local development, the same test-setup can be run locally via:

```shell
mvn clean install -Pdev
```

This will not tear-down the environement after the excution, thus can be used for testing/debugging from the IDE.
See [pom.xml](pom.xml)-Profile ```dev```-```k3s-maven-plugin``` for the available ports.

### Compatibility-Testing

To ensure compatibility with released Keycloak-Versions, the integration-tests support exectuion with different
Keycloak-Versions. In order to execute the tests with a specific version, provide either the
property ```keycloak.version```(which has to be a valid tag from the [official quay-image](quay.io/keycloak/keycloak))
or ```keycloak.image```. Be aware that the configuration might differ for different builds of Keycloak, thus alternative
images might require some additional changes in the k3s-setup. The compatibility tests are executed as part of the
pipeline and additionally once every night. The results can be found
at [the compatibility-matrix](./doc/compatibility/compatibility.md)
