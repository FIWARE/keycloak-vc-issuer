FROM quay.io/keycloak/keycloak:22.0
ENV KEYCLOAK_ADMIN=admin
ENV KEYCLOAK_ADMIN_PASSWORD=admin
#ENV KC_SPI_THEME_ADMIN_DEFAULT=siop-2
ENV VCISSUER_WALTID_ADDRESS=http://localhost
ENV VCISSUER_WALTID_SIGNATORY_PORT=6001
ADD src/test/resources/key.tls /opt/key.tls
ADD target/lib /opt/keycloak/providers/
ADD target/vc-issuer-0.0.1.jar /opt/keycloak/providers/vc-issuer-0.0.1.jar
