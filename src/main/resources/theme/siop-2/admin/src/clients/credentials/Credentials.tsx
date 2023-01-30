import { useState } from "react";
import { Controller, useFormContext, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";
import {
  Alert,
  ActionGroup,
  AlertVariant,
  Button,
  Card,
  CardBody,
  ClipboardCopy,
  Divider,
  FormGroup,
  PageSection,
  Select,
  SelectOption,
  SelectVariant,
  Split,
  SplitItem,
} from "@patternfly/react-core";

import type CredentialRepresentation from "@keycloak/keycloak-admin-client/lib/defs/credentialRepresentation";
import type { AuthenticationProviderRepresentation } from "@keycloak/keycloak-admin-client/lib/defs/authenticatorConfigRepresentation";
import type ClientRepresentation from "@keycloak/keycloak-admin-client/lib/defs/clientRepresentation";
import { useAlerts } from "../../components/alert/Alerts";
import { useConfirmDialog } from "../../components/confirm-dialog/ConfirmDialog";
import { FormAccess } from "../../components/form-access/FormAccess";
import { HelpItem } from "../../components/help-enabler/HelpItem";
import { useAdminClient, useFetch } from "../../context/auth/AdminClient";

import { ClientSecret } from "./ClientSecret";
import { SignedJWT } from "./SignedJWT";
import { X509 } from "./X509";
import "./credentials.css";

type AccessToken = {
  registrationAccessToken: string;
};

export type CredentialsProps = {
  client: ClientRepresentation;
  save: () => void;
  refresh: () => void;
};

export const Credentials = ({ client, save, refresh }: CredentialsProps) => {
  const { t } = useTranslation("clients");
  const { adminClient } = useAdminClient();
  const { addAlert, addError } = useAlerts();
  const clientId = client.id!;

  const [providers, setProviders] = useState<
    AuthenticationProviderRepresentation[]
  >([]);

  const {
    control,
    formState: { isDirty },
    handleSubmit,
  } = useFormContext<ClientRepresentation>();

  const clientAuthenticatorType = useWatch({
    control: control,
    name: "clientAuthenticatorType",
    defaultValue: "",
  });

  const [secret, setSecret] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [open, isOpen] = useState(false);

  useFetch(
    () =>
      Promise.all([
        adminClient.authenticationManagement.getClientAuthenticatorProviders(),
        adminClient.clients.getClientSecret({
          id: clientId,
        }),
      ]),
    ([providers, secret]) => {
      setProviders(providers);
      setSecret(secret.value!);
    },
    []
  );

  async function regenerate<T>(
    call: (clientId: string) => Promise<T>,
    message: string
  ): Promise<T | undefined> {
    try {
      const data = await call(clientId);
      addAlert(t(`${message}Success`), AlertVariant.success);
      return data;
    } catch (error) {
      addError(`clients:${message}Error`, error);
    }
  }

  const regenerateClientSecret = async () => {
    const secret = await regenerate<CredentialRepresentation>(
      (clientId) =>
        adminClient.clients.generateNewClientSecret({ id: clientId }),
      "clientSecret"
    );
    setSecret(secret?.value || "");
    refresh();
  };

  const [toggleClientSecretConfirm, ClientSecretConfirm] = useConfirmDialog({
    titleKey: "clients:confirmClientSecretTitle",
    messageKey: "clients:confirmClientSecretBody",
    continueButtonLabel: "common:yes",
    cancelButtonLabel: "common:no",
    onConfirm: regenerateClientSecret,
  });

  const regenerateAccessToken = async () => {
    const accessToken = await regenerate<AccessToken>(
      (clientId) =>
        adminClient.clients.generateRegistrationAccessToken({ id: clientId }),
      "accessToken"
    );
    setAccessToken(accessToken?.registrationAccessToken || "");
  };

  const [toggleAccessTokenConfirm, AccessTokenConfirm] = useConfirmDialog({
    titleKey: "clients:confirmAccessTokenTitle",
    messageKey: "clients:confirmAccessTokenBody",
    continueButtonLabel: "common:yes",
    cancelButtonLabel: "common:no",
    onConfirm: regenerateAccessToken,
  });

  return (
    <PageSection>
      <FormAccess
        onSubmit={handleSubmit(save)}
        isHorizontal
        className="pf-u-mt-md"
        role="manage-clients"
      >
        <ClientSecretConfirm />
        <AccessTokenConfirm />
        <Card isFlat>
          <CardBody>
            <FormGroup
              label={t("clientAuthenticator")}
              fieldId="kc-client-authenticator-type"
              labelIcon={
                <HelpItem
                  helpText="clients-help:client-authenticator-type"
                  fieldLabelId="clients:clientAuthenticator"
                />
              }
            >
              <Controller
                name="clientAuthenticatorType"
                control={control}
                defaultValue=""
                render={({ onChange, value }) => (
                  <Select
                    toggleId="kc-client-authenticator-type"
                    required
                    onToggle={isOpen}
                    onSelect={(_, value) => {
                      onChange(value as string);
                      isOpen(false);
                    }}
                    selections={value}
                    variant={SelectVariant.single}
                    aria-label={t("clientAuthenticator")}
                    isOpen={open}
                  >
                    {providers.map((option) => (
                      <SelectOption
                        selected={option.id === value}
                        key={option.id}
                        value={option.id}
                      >
                        {option.displayName}
                      </SelectOption>
                    ))}
                  </Select>
                )}
              />
            </FormGroup>
            {(clientAuthenticatorType === "client-jwt" ||
              clientAuthenticatorType === "client-secret-jwt") && <SignedJWT />}
            {clientAuthenticatorType === "client-jwt" && (
              <Alert
                variant="info"
                isInline
                className="kc-signedJWTAlert"
                title={t("signedJWTConfirm")}
              />
            )}
            {clientAuthenticatorType === "client-x509" && <X509 />}
            <ActionGroup>
              <Button variant="primary" type="submit" isDisabled={!isDirty}>
                {t("common:save")}
              </Button>
            </ActionGroup>
          </CardBody>
          {(clientAuthenticatorType === "client-secret" ||
            clientAuthenticatorType === "client-secret-jwt") && <Divider />}
          {(clientAuthenticatorType === "client-secret" ||
            clientAuthenticatorType === "client-secret-jwt") && (
            <CardBody>
              <ClientSecret
                client={client}
                secret={secret}
                toggle={toggleClientSecretConfirm}
              />
            </CardBody>
          )}
        </Card>
        <Card isFlat>
          <CardBody>
            <FormGroup
              label={t("registrationAccessToken")}
              fieldId="kc-access-token"
              labelIcon={
                <HelpItem
                  helpText="clients-help:registration-access-token"
                  fieldLabelId="clients:registrationAccessToken"
                />
              }
            >
              <Split hasGutter>
                <SplitItem isFilled>
                  <ClipboardCopy id="kc-access-token" isReadOnly>
                    {accessToken}
                  </ClipboardCopy>
                </SplitItem>
                <SplitItem>
                  <Button
                    variant="secondary"
                    onClick={toggleAccessTokenConfirm}
                  >
                    {t("regenerate")}
                  </Button>
                </SplitItem>
              </Split>
            </FormGroup>
          </CardBody>
        </Card>
      </FormAccess>
    </PageSection>
  );
};
