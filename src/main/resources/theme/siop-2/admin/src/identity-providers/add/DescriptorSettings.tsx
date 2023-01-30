import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Controller, useFormContext, useWatch } from "react-hook-form";
import {
  ExpandableSection,
  FormGroup,
  Select,
  SelectOption,
  SelectVariant,
  ValidatedOptions,
} from "@patternfly/react-core";
import { HelpItem } from "../../components/help-enabler/HelpItem";
import { SwitchField } from "../component/SwitchField";
import { TextField } from "../component/TextField";
import { KeycloakTextInput } from "../../components/keycloak-text-input/KeycloakTextInput";

import "./discovery-settings.css";

type DescriptorSettingsProps = {
  readOnly: boolean;
};

const Fields = ({ readOnly }: DescriptorSettingsProps) => {
  const { t } = useTranslation("identity-providers");
  const { t: th } = useTranslation("identity-providers-help");

  const {
    register,
    control,
    formState: { errors },
  } = useFormContext();
  const [namedPolicyDropdownOpen, setNamedPolicyDropdownOpen] = useState(false);
  const [principalTypeDropdownOpen, setPrincipalTypeDropdownOpen] =
    useState(false);
  const [signatureAlgorithmDropdownOpen, setSignatureAlgorithmDropdownOpen] =
    useState(false);
  const [
    samlSignatureKeyNameDropdownOpen,
    setSamlSignatureKeyNameDropdownOpen,
  ] = useState(false);

  const wantAuthnSigned = useWatch({
    control,
    name: "config.wantAuthnRequestsSigned",
  });

  const validateSignature = useWatch({
    control,
    name: "config.validateSignature",
  });

  const principalType = useWatch<string>({
    control,
    name: "config.principalType",
  });

  return (
    <div className="pf-c-form pf-m-horizontal">
      <FormGroup
        label={t("serviceProviderEntityId")}
        fieldId="kc-saml-service-provider-entity-id"
        labelIcon={
          <HelpItem
            helpText="identity-providers-help:serviceProviderEntityId"
            fieldLabelId="identity-providers:serviceProviderEntityId"
          />
        }
      >
        <KeycloakTextInput
          type="text"
          name="config.entityId"
          data-testid="serviceProviderEntityId"
          id="kc-saml-service-provider-entity-id"
          ref={register()}
        />
      </FormGroup>
      <FormGroup
        label={t("identityProviderEntityId")}
        fieldId="kc-identity-provider-entity-id"
        labelIcon={
          <HelpItem
            helpText="identity-providers-help:identityProviderEntityId"
            fieldLabelId="identity-providers:identityProviderEntityId"
          />
        }
      >
        <KeycloakTextInput
          type="text"
          name="config.idpEntityId"
          data-testid="identityProviderEntityId"
          id="kc-identity-provider-entity-id"
          ref={register()}
        />
      </FormGroup>
      <FormGroup
        label={t("ssoServiceUrl")}
        labelIcon={
          <HelpItem
            helpText={th("ssoServiceUrl")}
            fieldLabelId="identity-providers:ssoServiceUrl"
          />
        }
        fieldId="kc-sso-service-url"
        isRequired
        validated={
          errors.config?.authorizationUrl
            ? ValidatedOptions.error
            : ValidatedOptions.default
        }
        helperTextInvalid={t("common:required")}
      >
        <KeycloakTextInput
          type="text"
          data-testid="sso-service-url"
          id="kc-sso-service-url"
          name="config.singleSignOnServiceUrl"
          ref={register({ required: true })}
          validated={
            errors.config?.singleSignOnServiceUrl
              ? ValidatedOptions.error
              : ValidatedOptions.default
          }
          isReadOnly={readOnly}
        />
      </FormGroup>
      <FormGroup
        label={t("singleLogoutServiceUrl")}
        labelIcon={
          <HelpItem
            helpText={th("singleLogoutServiceUrl")}
            fieldLabelId="identity-providers:singleLogoutServiceUrl"
          />
        }
        fieldId="single-logout-service-url"
        validated={
          errors.config?.singleLogoutServiceUrl
            ? ValidatedOptions.error
            : ValidatedOptions.default
        }
        helperTextInvalid={t("common:required")}
      >
        <KeycloakTextInput
          type="text"
          id="single-logout-service-url"
          name="config.singleLogoutServiceUrl"
          ref={register}
          isReadOnly={readOnly}
        />
      </FormGroup>
      <SwitchField
        field="config.backchannelSupported"
        label="backchannelLogout"
        isReadOnly={readOnly}
      />
      <FormGroup
        label={t("nameIdPolicyFormat")}
        labelIcon={
          <HelpItem
            helpText={th("nameIdPolicyFormat")}
            fieldLabelId="identity-providers:nameIdPolicyFormat"
          />
        }
        fieldId="kc-nameIdPolicyFormat"
        helperTextInvalid={t("common:required")}
      >
        <Controller
          name="config.nameIDPolicyFormat"
          defaultValue={"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"}
          control={control}
          render={({ onChange, value }) => (
            <Select
              toggleId="kc-nameIdPolicyFormat"
              onToggle={(isExpanded) => setNamedPolicyDropdownOpen(isExpanded)}
              isOpen={namedPolicyDropdownOpen}
              onSelect={(_, value) => {
                onChange(value as string);
                setNamedPolicyDropdownOpen(false);
              }}
              selections={value}
              variant={SelectVariant.single}
              isDisabled={readOnly}
            >
              <SelectOption
                data-testid="persistent-option"
                value={"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"}
                isPlaceholder
              >
                {t("persistent")}
              </SelectOption>
              <SelectOption
                data-testid="transient-option"
                value="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
              >
                {t("transient")}
              </SelectOption>
              <SelectOption
                data-testid="email-option"
                value="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
              >
                {t("email")}
              </SelectOption>
              <SelectOption
                data-testid="kerberos-option"
                value="urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"
              >
                {t("kerberos")}
              </SelectOption>

              <SelectOption
                data-testid="x509-option"
                value="urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
              >
                {t("x509")}
              </SelectOption>

              <SelectOption
                data-testid="windowsDomainQN-option"
                value="urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
              >
                {t("windowsDomainQN")}
              </SelectOption>

              <SelectOption
                data-testid="unspecified-option"
                value={"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"}
              >
                {t("unspecified")}
              </SelectOption>
            </Select>
          )}
        ></Controller>
      </FormGroup>

      <FormGroup
        label={t("principalType")}
        labelIcon={
          <HelpItem
            helpText={th("principalType")}
            fieldLabelId="identity-providers:principalType"
          />
        }
        fieldId="kc-principalType"
        helperTextInvalid={t("common:required")}
      >
        <Controller
          name="config.principalType"
          defaultValue={t("subjectNameId")}
          control={control}
          render={({ onChange, value }) => (
            <Select
              toggleId="kc-principalType"
              onToggle={(isExpanded) =>
                setPrincipalTypeDropdownOpen(isExpanded)
              }
              isOpen={principalTypeDropdownOpen}
              onSelect={(_, value) => {
                onChange(value.toString());
                setPrincipalTypeDropdownOpen(false);
              }}
              selections={value}
              variant={SelectVariant.single}
              isDisabled={readOnly}
            >
              <SelectOption
                data-testid="subjectNameId-option"
                value="SUBJECT"
                isPlaceholder
              >
                {t("subjectNameId")}
              </SelectOption>
              <SelectOption
                data-testid="attributeName-option"
                value="ATTRIBUTE"
              >
                {t("attributeName")}
              </SelectOption>
              <SelectOption
                data-testid="attributeFriendlyName-option"
                value="FRIENDLY_ATTRIBUTE"
              >
                {t("attributeFriendlyName")}
              </SelectOption>
            </Select>
          )}
        ></Controller>
      </FormGroup>

      {principalType?.includes("ATTRIBUTE") && (
        <FormGroup
          label={t("principalAttribute")}
          labelIcon={
            <HelpItem
              helpText={th("principalAttribute")}
              fieldLabelId="identity-providers:principalAttribute"
            />
          }
          fieldId="principalAttribute"
        >
          <KeycloakTextInput
            type="text"
            id="principalAttribute"
            name="config.principalAttribute"
            ref={register}
            isReadOnly={readOnly}
          />
        </FormGroup>
      )}
      <SwitchField
        field="config.allowCreate"
        label="allowCreate"
        isReadOnly={readOnly}
      />

      <SwitchField
        field="config.postBindingResponse"
        label="httpPostBindingResponse"
        isReadOnly={readOnly}
      />

      <SwitchField
        field="config.postBindingAuthnRequest"
        label="httpPostBindingAuthnRequest"
        isReadOnly={readOnly}
      />

      <SwitchField
        field="config.postBindingLogout"
        label="httpPostBindingLogout"
        isReadOnly={readOnly}
      />

      <SwitchField
        field="config.wantAuthnRequestsSigned"
        label="wantAuthnRequestsSigned"
        isReadOnly={readOnly}
      />

      {wantAuthnSigned === "true" && (
        <>
          <FormGroup
            label={t("signatureAlgorithm")}
            labelIcon={
              <HelpItem
                helpText={th("signatureAlgorithm")}
                fieldLabelId="identity-providers:signatureAlgorithm"
              />
            }
            fieldId="kc-signatureAlgorithm"
          >
            <Controller
              name="config.signatureAlgorithm"
              defaultValue="RSA_SHA256"
              control={control}
              render={({ onChange, value }) => (
                <Select
                  toggleId="kc-signatureAlgorithm"
                  onToggle={(isExpanded) =>
                    setSignatureAlgorithmDropdownOpen(isExpanded)
                  }
                  isOpen={signatureAlgorithmDropdownOpen}
                  onSelect={(_, value) => {
                    onChange(value.toString());
                    setSignatureAlgorithmDropdownOpen(false);
                  }}
                  selections={value}
                  variant={SelectVariant.single}
                  isDisabled={readOnly}
                >
                  <SelectOption value="RSA_SHA1" />
                  <SelectOption value="RSA_SHA256" isPlaceholder />
                  <SelectOption value="RSA_SHA256_MGF1" />
                  <SelectOption value="RSA_SHA512" />
                  <SelectOption value="RSA_SHA512_MGF1" />
                  <SelectOption value="DSA_SHA1" />
                </Select>
              )}
            ></Controller>
          </FormGroup>
          <FormGroup
            label={t("samlSignatureKeyName")}
            labelIcon={
              <HelpItem
                helpText={th("samlSignatureKeyName")}
                fieldLabelId="identity-providers:samlSignatureKeyName"
              />
            }
            fieldId="kc-samlSignatureKeyName"
          >
            <Controller
              name="config.xmlSigKeyInfoKeyNameTransformer"
              defaultValue={t("keyID")}
              control={control}
              render={({ onChange, value }) => (
                <Select
                  toggleId="kc-samlSignatureKeyName"
                  onToggle={(isExpanded) =>
                    setSamlSignatureKeyNameDropdownOpen(isExpanded)
                  }
                  isOpen={samlSignatureKeyNameDropdownOpen}
                  onSelect={(_, value) => {
                    onChange(value.toString());
                    setSamlSignatureKeyNameDropdownOpen(false);
                  }}
                  selections={value}
                  variant={SelectVariant.single}
                  isDisabled={readOnly}
                >
                  <SelectOption value="NONE" />
                  <SelectOption value={t("keyID")} isPlaceholder />
                  <SelectOption value={t("certSubject")} />
                </Select>
              )}
            ></Controller>
          </FormGroup>
        </>
      )}

      <SwitchField
        field="config.wantAssertionsSigned"
        label="wantAssertionsSigned"
        isReadOnly={readOnly}
      />

      <SwitchField
        field="config.wantAssertionsEncrypted"
        label="wantAssertionsEncrypted"
        isReadOnly={readOnly}
      />
      <SwitchField
        field="config.forceAuthn"
        label="forceAuthentication"
        isReadOnly={readOnly}
      />

      <SwitchField
        field="config.validateSignature"
        label="validateSignature"
        isReadOnly={readOnly}
      />
      {validateSignature === "true" && (
        <TextField
          field="config.signingCertificate"
          label="validatingX509Certs"
          isReadOnly={readOnly}
        />
      )}
      <SwitchField
        field="config.signSpMetadata"
        label="signServiceProviderMetadata"
        isReadOnly={readOnly}
      />
      <SwitchField
        field="config.loginHint"
        label="passSubject"
        isReadOnly={readOnly}
      />

      <FormGroup
        label={t("allowedClockSkew")}
        labelIcon={
          <HelpItem
            helpText={th("allowedClockSkew")}
            fieldLabelId="identity-providers:allowedClockSkew"
          />
        }
        fieldId="allowedClockSkew"
        helperTextInvalid={t("common:required")}
      >
        <KeycloakTextInput
          type="number"
          min="0"
          max="2147483"
          id="allowedClockSkew"
          name="config.allowedClockSkew"
          ref={register}
          isReadOnly={readOnly}
        />
      </FormGroup>

      <FormGroup
        label={t("attributeConsumingServiceIndex")}
        labelIcon={
          <HelpItem
            helpText={th("attributeConsumingServiceIndex")}
            fieldLabelId="identity-providers:attributeConsumingServiceIndex"
          />
        }
        fieldId="attributeConsumingServiceIndex"
        helperTextInvalid={t("common:required")}
      >
        <KeycloakTextInput
          type="number"
          min="0"
          max="65535"
          id="attributeConsumingServiceIndex"
          name="config.attributeConsumingServiceIndex"
          ref={register}
          isReadOnly={readOnly}
        />
      </FormGroup>

      <FormGroup
        label={t("attributeConsumingServiceName")}
        labelIcon={
          <HelpItem
            helpText={th("attributeConsumingServiceName")}
            fieldLabelId="identity-providers:attributeConsumingServiceName"
          />
        }
        fieldId="attributeConsumingServiceName"
        helperTextInvalid={t("common:required")}
      >
        <KeycloakTextInput
          type="text"
          id="attributeConsumingServiceName"
          name="config.attributeConsumingServiceName"
          ref={register}
          isReadOnly={readOnly}
        />
      </FormGroup>
    </div>
  );
};

export const DescriptorSettings = ({ readOnly }: DescriptorSettingsProps) => {
  const { t } = useTranslation("identity-providers");
  const [isExpanded, setIsExpanded] = useState(false);

  return readOnly ? (
    <ExpandableSection
      className="keycloak__discovery-settings__metadata"
      toggleText={isExpanded ? t("hideMetaData") : t("showMetaData")}
      onToggle={(isOpen) => setIsExpanded(isOpen)}
      isExpanded={isExpanded}
    >
      <Fields readOnly={readOnly} />
    </ExpandableSection>
  ) : (
    <Fields readOnly={readOnly} />
  );
};
