# Keycloak VC-Issuer

[![FIWARE Security](https://nexus.lab.fiware.org/repository/raw/public/badges/chapters/security.svg)](https://www.fiware.org/developers/catalogue/)
[![License badge](https://img.shields.io/github/license/FIWARE/context.Orion-LD.svg)](https://opensource.org/licenses/AGPL-3.0)
[![Container Repository on Quay](https://img.shields.io/badge/quay.io-VCIssuer-green "Container Repository on Quay")](https://quay.io/repository/fiware/keycloak-vc-issuer)
[![Integration-Test](https://github.com/FIWARE/keycloak-vc-issuer/actions/workflows/integration-test.yaml/badge.svg)](https://github.com/FIWARE/keycloak-vc-issuer/actions/workflows/integration-test.yaml)
[![Unit-Test](https://github.com/FIWARE/keycloak-vc-issuer/actions/workflows/test.yaml/badge.svg)](https://github.com/FIWARE/keycloak-vc-issuer/actions/workflows/test.yaml)

A plugin for [Keycloak](https://www.keycloak.org/) to issue [VerifiableCredentials](https://www.w3.org/TR/vc-data-model/).

## Compatibility

The plugin is developed with the [20.0.3 libraries](https://github.com/keycloak/keycloak/tree/20.0.3) and tested against
all Keycloak Minor-Releases >=18.0.0. Please check the [Compatibility-Matrix](./doc/compatibility/compatibility.md) for more information. 
The matrix gets updated every night.

## Functionality

The VC-Issuer plugin provides an integration [VerifiableCredentials](https://www.w3.org/TR/vc-data-model/)
into [Keycloak](https://www.keycloak.org/). It allows to manage potential receivers of VerifiableCredentials
as [SIOP-2 Clients](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html), allowing to manage users and roles
in the well-known Keycloak way. In addition to that, it provides the endpoints for (authenticated) users to receive
VerifiableCredentials for their account. To integrate with the Account-Console frontend, the SIOP-2 Theme is included.

## Dependencies & Configuration

In order to provide the capabilities of issuing VerifiableCredentials and handling DIDs, Keycloak relies
on [Walt-ID](https://github.com/walt-id/waltid-ssikit)
as a downstream component. The [integration-test setup](src/test/k3s) provides an example on how to run and integrate
it. The configuration is provided via environment variables:

|Name| Description                                                                          | Default    |
|----|--------------------------------------------------------------------------------------|------------|
|VCISSUER_WALTID_ADDRESS| Base address of walt-id. Has to include the protocol.                                ||
|VCISSUER_WALTID_CORE_PORT| Port to be used for connecting the walt-id's core-api.                               | ```7000``` |
|VCISSUER_WALTID_SIGNATORY_PORT| Port to be used for connecting the walt-id's signatory-api.                          | ```7001``` |
|VCISSUER_ISSUER_DID| DID to be used for issuing credentials. If none is provided, Keycloak will create one. | |
|VCISSUER_ISSUER_KEY_FILE| Path to the file containing the issuer key.                                          | |

## Usage

### Api

The plugin provides two endpoints through its API ([see OpenApi-Doc](./doc/api.yaml)) as a realm resource:

- /realms/{realm}/types - returns the list of types supported by the SIOP-2 clients, that can be requested as a
  VerifiableCredential
- /realms/{realm}/verifiable-credential - returns the credential requested in the types parameter

The APIs are only available to authenticated and authorized users. In order to support retrieval by wallets, the
requests can not only be authorized via ```Authorization```-header, but also via the ```token```-parameter.

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
  "attributes": {
    "expiryInMin": "3600",
    "supportedVCTypes": "BatteryPassAuthCredential"
  }
}
```
Once the client is created, roles and role-assignemnts can be managed the same way as for every other type, through the API or the Admin-Console.

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
    "supportedVCTypes": "PacketDeliveryService",
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

## Deployment

The VC Issuer is a fully-self-contained provider, thus the jar-file only has to be added to the ```providers```-folder
of Keycloak(typically under ```/opt/keycloak/providers```). Keycloak will automatically pick-up the provider at
start-time. The plugin is available as jar-file through [the github-releases](https://github.com/wistefan/keycloak-vc-issuer/releases) or
as a [container at quay.io](https://quay.io/repository/fiware/keycloak-vc-issuer). The container can for example be used 
as an init-container, to copy the jar file into a shared folder and make it available for Keycloak.

To have the account-console integration, the ```SIOP-2```-theme has to be enabled for the realm:

![setup-theme](doc/siop-theme.png)

In addition to Keycloak, an installation of [WaltID-SSIKit](https://github.com/walt-id/waltid-ssikit) needs to be
provided. Keycloak uses it, to create the actual credentials. It can f.e. be deployed
via [Helm-Chart](https://github.com/i4Trust/helm-charts/tree/main/charts/vcwaltid).