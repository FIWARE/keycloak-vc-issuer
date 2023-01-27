# Keycloak VC-Issuer

A plugin for Keycloak >=20.0.3 issuing Verifiable Credentials to registered users.

## Functionality 

The VC-Issuer plugin provides an integration [VerifiableCredentials](https://www.w3.org/TR/vc-data-model/) into [Keycloak](https://www.keycloak.org/).
It allows to manage potential receivers of VerifiableCredentials as [SIOP-2 Clients](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html),
allowing to manage users and roles in the well-known Keycloak way. 
In addition to that, it provides the endpoints for (authenticated) users to receive VerifiableCredentials for their account. To integrate
with the Account-Console frontend, the SIOP-2 Theme is included.

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
created and assigned to users. Once that is done, a logged in user can use the account-interface to get Verifiable Credentials:

Account-Console overview:

![account-console](doc/account.png)

Get a VC:

![get-vc](doc/vc.png)

## Deployment

The VC Issuer is a fully-self-contained provider, thus the jar-file only has to be added to the ```providers```-folder of Keycloak(typically under ```/opt/keycloak/providers```).
Keycloak will automatically pick-up the provider at start-time. To have the account-console integration, the ```SIOP-2```-theme has to be 
enabled for the realm:

![setup-theme](doc/siop-theme.png)