import type { UserProfileGroup } from "@keycloak/keycloak-admin-client/lib/defs/userProfileConfig";
import {
  ActionGroup,
  Button,
  FormGroup,
  PageSection,
  Text,
  TextContent,
} from "@patternfly/react-core";
import { useEffect, useMemo } from "react";
import { FormProvider, SubmitHandler, useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { useParams } from "react-router-dom";
import { Link, useNavigate } from "react-router-dom-v5-compat";
import { KeyValueInput } from "../../components/key-value-form/KeyValueInput";
import { FormAccess } from "../../components/form-access/FormAccess";
import { HelpItem } from "../../components/help-enabler/HelpItem";
import { KeycloakTextInput } from "../../components/keycloak-text-input/KeycloakTextInput";
import { ViewHeader } from "../../components/view-header/ViewHeader";
import { useRealm } from "../../context/realm-context/RealmContext";
import type { EditAttributesGroupParams } from "../routes/EditAttributesGroup";
import { toUserProfile } from "../routes/UserProfile";
import { useUserProfile } from "./UserProfileContext";
import type { KeyValueType } from "../../components/key-value-form/key-value-convert";

import "../realm-settings-section.css";

function parseAnnotations(input: Record<string, unknown>): KeyValueType[] {
  return Object.entries(input).reduce((p, [key, value]) => {
    if (typeof value === "string") {
      return [...p, { key, value }];
    } else {
      return [...p];
    }
  }, [] as KeyValueType[]);
}

function transformAnnotations(input: KeyValueType[]): Record<string, unknown> {
  return Object.fromEntries(
    input
      .filter((annotation) => annotation.key.length > 0)
      .map((annotation) => [annotation.key, annotation.value] as const)
  );
}

type FormFields = Required<Omit<UserProfileGroup, "annotations">> & {
  annotations: KeyValueType[];
};

const defaultValues: FormFields = {
  annotations: [{ key: "", value: "" }],
  displayDescription: "",
  displayHeader: "",
  name: "",
};

export default function AttributesGroupForm() {
  const { t } = useTranslation();
  const { realm } = useRealm();
  const { config, save } = useUserProfile();
  const navigate = useNavigate();
  const params = useParams<Partial<EditAttributesGroupParams>>();
  const form = useForm<FormFields>({ defaultValues, shouldUnregister: false });

  const matchingGroup = useMemo(
    () => config?.groups?.find(({ name }) => name === params.name),
    [config?.groups]
  );

  useEffect(() => {
    if (!matchingGroup) {
      return;
    }

    const annotations = matchingGroup.annotations
      ? parseAnnotations(matchingGroup.annotations)
      : [];

    form.reset({ ...defaultValues, ...matchingGroup, annotations });
  }, [matchingGroup]);

  const onSubmit: SubmitHandler<FormFields> = async (values) => {
    if (!config) {
      return;
    }

    const groups = [...(config.groups ?? [])];
    const updateAt = matchingGroup ? groups.indexOf(matchingGroup) : -1;
    const updatedGroup: UserProfileGroup = {
      ...values,
      annotations: transformAnnotations(values.annotations),
    };

    if (updateAt === -1) {
      groups.push(updatedGroup);
    } else {
      groups[updateAt] = updatedGroup;
    }

    const success = await save({ ...config, groups });

    if (success) {
      navigate(toUserProfile({ realm, tab: "attributes-group" }));
    }
  };

  return (
    <>
      <ViewHeader
        titleKey={
          matchingGroup
            ? "attributes-group:editGroupText"
            : "attributes-group:createGroupText"
        }
        divider
      />
      <PageSection variant="light" onSubmit={form.handleSubmit(onSubmit)}>
        <FormAccess isHorizontal role="manage-realm">
          <FormGroup
            label={t("attributes-group:nameField")}
            fieldId="kc-name"
            isRequired
            helperTextInvalid={t("common:required")}
            validated={form.errors.name ? "error" : "default"}
            labelIcon={
              <HelpItem
                helpText="attributes-group:nameHint"
                fieldLabelId="attributes-group:nameField"
              />
            }
          >
            <KeycloakTextInput
              ref={form.register({ required: true })}
              type="text"
              id="kc-name"
              name="name"
              isReadOnly={!!matchingGroup}
            />
            {!!matchingGroup && (
              <input type="hidden" ref={form.register()} name="name" />
            )}
          </FormGroup>
          <FormGroup
            label={t("attributes-group:displayHeaderField")}
            fieldId="kc-display-header"
            labelIcon={
              <HelpItem
                helpText="attributes-group:displayHeaderHint"
                fieldLabelId="attributes-group:displayHeaderField"
              />
            }
          >
            <KeycloakTextInput
              ref={form.register()}
              type="text"
              id="kc-display-header"
              name="displayHeader"
            />
          </FormGroup>
          <FormGroup
            label={t("attributes-group:displayDescriptionField")}
            fieldId="kc-display-description"
            labelIcon={
              <HelpItem
                helpText="attributes-group:displayDescriptionHint"
                fieldLabelId="attributes-group:displayDescriptionField"
              />
            }
          >
            <KeycloakTextInput
              ref={form.register()}
              type="text"
              id="kc-display-description"
              name="displayDescription"
            />
          </FormGroup>
          <TextContent>
            <Text component="h2">{t("attributes-group:annotationsText")}</Text>
          </TextContent>
          <FormGroup
            label={t("attributes-group:annotationsText")}
            fieldId="kc-annotations"
          >
            <FormProvider {...form}>
              <KeyValueInput name="annotations" />
            </FormProvider>
          </FormGroup>
          <ActionGroup>
            <Button variant="primary" type="submit">
              {t("common:save")}
            </Button>
            <Button
              variant="link"
              component={(props) => (
                <Link
                  {...props}
                  to={toUserProfile({ realm, tab: "attributes-group" })}
                />
              )}
            >
              {t("common:cancel")}
            </Button>
          </ActionGroup>
        </FormAccess>
      </PageSection>
    </>
  );
}
