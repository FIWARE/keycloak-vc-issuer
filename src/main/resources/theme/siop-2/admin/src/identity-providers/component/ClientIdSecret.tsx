import { useTranslation } from "react-i18next";
import { useFormContext } from "react-hook-form";
import { FormGroup, ValidatedOptions } from "@patternfly/react-core";

import { HelpItem } from "../../components/help-enabler/HelpItem";
import { PasswordInput } from "../../components/password-input/PasswordInput";
import { KeycloakTextInput } from "../../components/keycloak-text-input/KeycloakTextInput";

export const ClientIdSecret = ({
  secretRequired = true,
  create = true,
}: {
  secretRequired?: boolean;
  create?: boolean;
}) => {
  const { t } = useTranslation("identity-providers");

  const {
    register,
    formState: { errors },
  } = useFormContext();

  return (
    <>
      <FormGroup
        label={t("clientId")}
        labelIcon={
          <HelpItem
            helpText="identity-providers-help:clientId"
            fieldLabelId="identity-providers:clientId"
          />
        }
        fieldId="kc-client-id"
        isRequired
        validated={
          errors.config?.clientId
            ? ValidatedOptions.error
            : ValidatedOptions.default
        }
        helperTextInvalid={t("common:required")}
      >
        <KeycloakTextInput
          isRequired
          type="text"
          id="kc-client-id"
          data-testid="clientId"
          name="config.clientId"
          ref={register({ required: true })}
        />
      </FormGroup>
      <FormGroup
        label={t("clientSecret")}
        labelIcon={
          <HelpItem
            helpText="identity-providers-help:clientSecret"
            fieldLabelId="identity-providers:clientSecret"
          />
        }
        fieldId="kc-client-secret"
        isRequired={secretRequired}
        validated={
          errors.config?.clientSecret
            ? ValidatedOptions.error
            : ValidatedOptions.default
        }
        helperTextInvalid={t("common:required")}
      >
        {create && (
          <PasswordInput
            isRequired={secretRequired}
            id="kc-client-secret"
            data-testid="clientSecret"
            name="config.clientSecret"
            ref={register({ required: secretRequired })}
          />
        )}
        {!create && (
          <KeycloakTextInput
            isRequired={secretRequired}
            type="password"
            id="kc-client-secret"
            data-testid="clientSecret"
            name="config.clientSecret"
            ref={register({ required: secretRequired })}
          />
        )}
      </FormGroup>
    </>
  );
};
