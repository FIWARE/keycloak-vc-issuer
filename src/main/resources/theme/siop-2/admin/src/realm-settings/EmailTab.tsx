import type RealmRepresentation from "@keycloak/keycloak-admin-client/lib/defs/realmRepresentation";
import {
  ActionGroup,
  ActionListItem,
  Alert,
  AlertActionLink,
  AlertVariant,
  Button,
  Checkbox,
  FormGroup,
  PageSection,
  Switch,
} from "@patternfly/react-core";
import { useState } from "react";
import { Controller, useForm, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom-v5-compat";

import { useAlerts } from "../components/alert/Alerts";
import { FormAccess } from "../components/form-access/FormAccess";
import { HelpItem } from "../components/help-enabler/HelpItem";
import { KeycloakTextInput } from "../components/keycloak-text-input/KeycloakTextInput";
import { PasswordInput } from "../components/password-input/PasswordInput";
import { FormPanel } from "../components/scroll-form/FormPanel";
import { useAdminClient } from "../context/auth/AdminClient";
import { useRealm } from "../context/realm-context/RealmContext";
import { toUser } from "../user/routes/User";
import { emailRegexPattern } from "../util";
import { useCurrentUser } from "../utils/useCurrentUser";

import "./realm-settings-section.css";
import useToggle from "../utils/useToggle";

type RealmSettingsEmailTabProps = {
  realm: RealmRepresentation;
};

export const RealmSettingsEmailTab = ({
  realm: initialRealm,
}: RealmSettingsEmailTabProps) => {
  const { t } = useTranslation("realm-settings");
  const { adminClient } = useAdminClient();
  const { realm: realmName } = useRealm();
  const { addAlert, addError } = useAlerts();
  const currentUser = useCurrentUser();

  const [realm, setRealm] = useState(initialRealm);
  const {
    register,
    control,
    handleSubmit,
    watch,
    reset: resetForm,
    getValues,
    formState: { errors },
  } = useForm<RealmRepresentation>({ defaultValues: realm });

  const reset = () => resetForm(realm);
  const watchFromValue = watch("smtpServer.from", "");
  const watchHostValue = watch("smtpServer.host", "");
  const [isTesting, toggleTest] = useToggle();

  const authenticationEnabled = useWatch({
    control,
    name: "smtpServer.auth",
    defaultValue: "",
  });

  const save = async (form: RealmRepresentation) => {
    try {
      const savedRealm = { ...realm, ...form };

      // For default value, back end is expecting null instead of empty string
      if (savedRealm.smtpServer?.port === "") savedRealm.smtpServer.port = null;

      await adminClient.realms.update({ realm: realmName }, savedRealm);
      setRealm(savedRealm);
      addAlert(t("saveSuccess"), AlertVariant.success);
    } catch (error) {
      addError("realm-settings:saveError", error);
    }
  };

  const testConnection = async () => {
    const toNumber = (value: string) => Number(value);
    const toBoolean = (value: string) => value === true.toString();
    const valueMapper = new Map<string, (value: string) => unknown>([
      ["port", toNumber],
      ["ssl", toBoolean],
      ["starttls", toBoolean],
      ["auth", toBoolean],
    ]);

    const serverSettings = { ...getValues()["smtpServer"] };

    for (const [key, mapperFn] of valueMapper.entries()) {
      serverSettings[key] = mapperFn(serverSettings[key]);
    }

    // For default value, back end is expecting null instead of 0
    if (serverSettings.port === 0) serverSettings.port = null;

    try {
      toggleTest();
      await adminClient.realms.testSMTPConnection(
        { realm: realm.realm! },
        serverSettings
      );
      addAlert(t("testConnectionSuccess"), AlertVariant.success);
    } catch (error) {
      addError("realm-settings:testConnectionError", error);
    }
    toggleTest();
  };

  return (
    <PageSection variant="light">
      <FormPanel title={t("template")} className="kc-email-template">
        <FormAccess
          isHorizontal
          role="manage-realm"
          className="pf-u-mt-lg"
          onSubmit={handleSubmit(save)}
        >
          <FormGroup
            label={t("from")}
            fieldId="kc-display-name"
            isRequired
            validated={errors.smtpServer?.from ? "error" : "default"}
            helperTextInvalid={t("users:emailInvalid")}
          >
            <KeycloakTextInput
              type="email"
              id="kc-sender-email-address"
              data-testid="sender-email-address"
              name="smtpServer.from"
              ref={register({
                pattern: emailRegexPattern,
                required: true,
              })}
              placeholder="Sender email address"
              validated={errors.smtpServer?.from ? "error" : "default"}
            />
          </FormGroup>
          <FormGroup
            label={t("fromDisplayName")}
            fieldId="kc-from-display-name"
            labelIcon={
              <HelpItem
                helpText="realm-settings-help:fromDisplayName"
                fieldLabelId="realm-settings:authentication"
              />
            }
          >
            <KeycloakTextInput
              type="text"
              id="kc-from-display-name"
              data-testid="from-display-name"
              name="smtpServer.fromDisplayName"
              ref={register}
              placeholder="Display name for Sender email address"
            />
          </FormGroup>
          <FormGroup
            label={t("replyTo")}
            fieldId="kc-reply-to"
            validated={errors.smtpServer?.replyTo ? "error" : "default"}
            helperTextInvalid={t("users:emailInvalid")}
          >
            <KeycloakTextInput
              type="email"
              id="kc-reply-to"
              name="smtpServer.replyTo"
              ref={register({
                pattern: emailRegexPattern,
              })}
              placeholder="Reply to email address"
              validated={errors.smtpServer?.replyTo ? "error" : "default"}
            />
          </FormGroup>
          <FormGroup
            label={t("replyToDisplayName")}
            fieldId="kc-reply-to-display-name"
            labelIcon={
              <HelpItem
                helpText="realm-settings-help:replyToDisplayName"
                fieldLabelId="realm-settings:replyToDisplayName"
              />
            }
          >
            <KeycloakTextInput
              type="text"
              id="kc-reply-to-display-name"
              name="smtpServer.replyToDisplayName"
              ref={register}
              placeholder='Display name for "reply to" email address'
            />
          </FormGroup>
          <FormGroup
            label={t("envelopeFrom")}
            fieldId="kc-envelope-from"
            labelIcon={
              <HelpItem
                helpText="realm-settings-help:envelopeFrom"
                fieldLabelId="realm-settings:envelopeFrom"
              />
            }
          >
            <KeycloakTextInput
              type="text"
              id="kc-envelope-from"
              name="smtpServer.envelopeFrom"
              ref={register}
              placeholder="Sender envelope email address"
            />
          </FormGroup>
        </FormAccess>
      </FormPanel>
      <FormPanel
        className="kc-email-connection"
        title={t("connectionAndAuthentication")}
      >
        <FormAccess
          isHorizontal
          role="manage-realm"
          className="pf-u-mt-lg"
          onSubmit={handleSubmit(save)}
        >
          <FormGroup
            label={t("host")}
            fieldId="kc-host"
            isRequired
            validated={errors.smtpServer?.host ? "error" : "default"}
            helperTextInvalid={t("common:required")}
          >
            <KeycloakTextInput
              type="text"
              id="kc-host"
              name="smtpServer.host"
              ref={register({ required: true })}
              placeholder="SMTP host"
              validated={errors.smtpServer?.host ? "error" : "default"}
            />
          </FormGroup>
          <FormGroup label={t("port")} fieldId="kc-port">
            <KeycloakTextInput
              type="text"
              id="kc-port"
              name="smtpServer.port"
              ref={register}
              placeholder="SMTP port (defaults to 25)"
            />
          </FormGroup>
          <FormGroup label={t("encryption")} fieldId="kc-html-display-name">
            <Controller
              name="smtpServer.ssl"
              control={control}
              defaultValue="false"
              render={({ onChange, value }) => (
                <Checkbox
                  id="kc-enable-ssl"
                  data-testid="enable-ssl"
                  label={t("enableSSL")}
                  ref={register}
                  isChecked={value === "true"}
                  onChange={(value) => onChange("" + value)}
                />
              )}
            />
            <Controller
              name="smtpServer.starttls"
              control={control}
              defaultValue="false"
              render={({ onChange, value }) => (
                <Checkbox
                  id="kc-enable-start-tls"
                  data-testid="enable-start-tls"
                  label={t("enableStartTLS")}
                  ref={register}
                  isChecked={value === "true"}
                  onChange={(value) => onChange("" + value)}
                />
              )}
            />
          </FormGroup>
          <FormGroup
            hasNoPaddingTop
            label={t("authentication")}
            fieldId="kc-authentication"
          >
            <Controller
              name="smtpServer.auth"
              control={control}
              defaultValue=""
              render={({ onChange, value }) => (
                <Switch
                  id="kc-authentication-switch"
                  data-testid="email-authentication-switch"
                  label={t("common:enabled")}
                  labelOff={t("common:disabled")}
                  isChecked={value === "true"}
                  onChange={(value) => {
                    onChange("" + value);
                  }}
                  aria-label={t("authentication")}
                />
              )}
            />
          </FormGroup>
          {authenticationEnabled === "true" && (
            <>
              <FormGroup
                label={t("username")}
                fieldId="kc-username"
                isRequired
                validated={errors.smtpServer?.user ? "error" : "default"}
                helperTextInvalid={t("common:required")}
              >
                <KeycloakTextInput
                  type="text"
                  id="kc-username"
                  data-testid="username-input"
                  name="smtpServer.user"
                  ref={register({ required: true })}
                  placeholder="Login username"
                  validated={errors.smtpServer?.user ? "error" : "default"}
                />
              </FormGroup>
              <FormGroup
                label={t("password")}
                fieldId="kc-username"
                isRequired
                validated={errors.smtpServer?.password ? "error" : "default"}
                helperTextInvalid={t("common:required")}
                labelIcon={
                  <HelpItem
                    helpText="realm-settings-help:password"
                    fieldLabelId="realm-settings:password"
                  />
                }
              >
                <PasswordInput
                  id="kc-password"
                  data-testid="password-input"
                  name="smtpServer.password"
                  aria-label={t("password")}
                  validated={errors.smtpServer?.password ? "error" : "default"}
                  ref={register({ required: true })}
                />
              </FormGroup>
            </>
          )}

          <ActionGroup>
            <ActionListItem>
              <Button
                variant="primary"
                type="submit"
                data-testid="email-tab-save"
              >
                {t("common:save")}
              </Button>
            </ActionListItem>
            <ActionListItem>
              <Button
                variant="secondary"
                onClick={() => testConnection()}
                data-testid="test-connection-button"
                isDisabled={
                  !(emailRegexPattern.test(watchFromValue) && watchHostValue) ||
                  !currentUser?.email
                }
                aria-describedby="descriptionTestConnection"
                isLoading={isTesting}
                spinnerAriaValueText={t("testingConnection")}
              >
                {t("common:testConnection")}
              </Button>
            </ActionListItem>
            <ActionListItem>
              <Button
                variant="link"
                onClick={reset}
                data-testid="email-tab-revert"
              >
                {t("common:revert")}
              </Button>
            </ActionListItem>
          </ActionGroup>
          {currentUser && (
            <FormGroup id="descriptionTestConnection">
              {currentUser.email ? (
                <Alert
                  variant="info"
                  isInline
                  title={t("testConnectionHint.withEmail", {
                    email: currentUser.email,
                  })}
                />
              ) : (
                <Alert
                  variant="warning"
                  isInline
                  title={t("testConnectionHint.withoutEmail", {
                    userName: currentUser.username,
                  })}
                  actionLinks={
                    <AlertActionLink
                      component={(props) => (
                        <Link
                          {...props}
                          to={toUser({
                            realm: realmName,
                            id: currentUser.id!,
                            tab: "settings",
                          })}
                        />
                      )}
                    >
                      {t("testConnectionHint.withoutEmailAction")}
                    </AlertActionLink>
                  }
                />
              )}
            </FormGroup>
          )}
        </FormAccess>
      </FormPanel>
    </PageSection>
  );
};
