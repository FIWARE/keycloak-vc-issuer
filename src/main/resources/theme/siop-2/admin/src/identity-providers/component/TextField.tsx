import { useFormContext } from "react-hook-form";

import { FieldProps, FormGroupField } from "./FormGroupField";
import { KeycloakTextInput } from "../../components/keycloak-text-input/KeycloakTextInput";

export const TextField = ({ label, field, isReadOnly = false }: FieldProps) => {
  const { register } = useFormContext();
  return (
    <FormGroupField label={label}>
      <KeycloakTextInput
        type="text"
        id={label}
        data-testid={label}
        name={field}
        ref={register}
        isReadOnly={isReadOnly}
      />
    </FormGroupField>
  );
};
