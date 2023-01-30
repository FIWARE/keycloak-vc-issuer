import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Controller, useFormContext } from "react-hook-form";
import {
  SelectOption,
  FormGroup,
  Select,
  SelectVariant,
} from "@patternfly/react-core";

import type UserRepresentation from "@keycloak/keycloak-admin-client/lib/defs/userRepresentation";
import type { UserQuery } from "@keycloak/keycloak-admin-client/lib/resources/users";
import type { ComponentProps } from "../dynamic/components";

import { useAdminClient, useFetch } from "../../context/auth/AdminClient";
import { HelpItem } from "../help-enabler/HelpItem";
import useToggle from "../../utils/useToggle";

type UserSelectProps = ComponentProps & {
  variant?: SelectVariant;
  isRequired?: boolean;
};

export const UserSelect = ({
  name,
  label,
  helpText,
  defaultValue,
  isRequired,
  variant = SelectVariant.typeaheadMulti,
}: UserSelectProps) => {
  const { t } = useTranslation("clients");
  const {
    control,
    getValues,
    formState: { errors },
  } = useFormContext();
  const values: string[] | undefined = getValues(name!);

  const [open, toggleOpen] = useToggle();
  const [users, setUsers] = useState<(UserRepresentation | undefined)[]>([]);
  const [search, setSearch] = useState("");

  const { adminClient } = useAdminClient();

  useFetch(
    () => {
      const params: UserQuery = {
        max: 20,
      };
      if (search) {
        params.username = search;
      }

      if (values?.length && !search) {
        return Promise.all(
          values.map((id: string) => adminClient.users.findOne({ id }))
        );
      }
      return adminClient.users.find(params);
    },
    setUsers,
    [search]
  );

  const convert = (clients: (UserRepresentation | undefined)[]) =>
    clients
      .filter((c) => c !== undefined)
      .map((option) => (
        <SelectOption
          key={option!.id}
          value={option!.id}
          selected={values?.includes(option!.id!)}
        >
          {option!.username}
        </SelectOption>
      ));

  return (
    <FormGroup
      label={t(label!)}
      isRequired={isRequired}
      labelIcon={
        <HelpItem helpText={helpText!} fieldLabelId={`clients:${label}`} />
      }
      fieldId={name!}
      validated={errors[name!] ? "error" : "default"}
      helperTextInvalid={t("common:required")}
    >
      <Controller
        name={name!}
        defaultValue={defaultValue}
        control={control}
        rules={
          isRequired && variant === SelectVariant.typeaheadMulti
            ? { validate: (value) => value.length > 0 }
            : isRequired
            ? { required: true }
            : {}
        }
        render={({ onChange, value }) => (
          <Select
            toggleId={name!}
            variant={variant}
            placeholderText={t("selectAUser")}
            onToggle={toggleOpen}
            isOpen={open}
            selections={value}
            onFilter={(_, value) => {
              setSearch(value);
              return convert(users);
            }}
            onSelect={(_, v) => {
              const option = v.toString();
              if (value.includes(option)) {
                onChange(value.filter((item: string) => item !== option));
              } else {
                onChange([...value, option]);
              }
              toggleOpen();
            }}
            aria-label={t(name!)}
          >
            {convert(users)}
          </Select>
        )}
      />
    </FormGroup>
  );
};
