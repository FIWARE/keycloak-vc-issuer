import { useTranslation } from "react-i18next";
import { useFormContext } from "react-hook-form";
import { FormGroup } from "@patternfly/react-core";

import { HelpItem } from "../help-enabler/HelpItem";
import { KeycloakTextArea } from "../keycloak-text-area/KeycloakTextArea";
import type { ComponentProps } from "./components";
import { convertToName } from "./DynamicComponents";

export const TextComponent = ({
  name,
  label,
  helpText,
  defaultValue,
  isDisabled = false,
}: ComponentProps) => {
  const { t } = useTranslation("dynamic");
  const { register } = useFormContext();

  return (
    <FormGroup
      label={t(label!)}
      labelIcon={
        <HelpItem helpText={t(helpText!)} fieldLabelId={`dynamic:${label}`} />
      }
      fieldId={name!}
    >
      <KeycloakTextArea
        id={name!}
        data-testid={name}
        isDisabled={isDisabled}
        ref={register()}
        name={convertToName(name!)}
        defaultValue={defaultValue?.toString()}
      />
    </FormGroup>
  );
};
