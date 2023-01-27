FROM quay.io/keycloak/keycloak:20.0.3
ENV KEYCLOAK_ADMIN=admin
ENV KEYCLOAK_ADMIN_PASSWORD=admin
ENV VCISSUER_ISSUER_DID=did:key:z6Mkn6xvsBwANMuEN2MejbjbVMeV7pUVib6eU8Y14rF745oV
ENV VCISSUER_WALTID_ADDRESS=http://localhost:6001/v1/credentials/issue
ADD target/vc-issuer-SNAPSHOT-2.jar /opt/keycloak/providers/vc-issuer-SNAPSHOT-2.jar