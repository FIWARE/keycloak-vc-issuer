import {
  ActionGroup,
  AlertVariant,
  Button,
  Form,
  PageSection,
} from "@patternfly/react-core";

import { KerberosSettingsRequired } from "./kerberos/KerberosSettingsRequired";
import { SettingsCache } from "./shared/SettingsCache";
import { useRealm } from "../context/realm-context/RealmContext";
import type ComponentRepresentation from "@keycloak/keycloak-admin-client/lib/defs/componentRepresentation";

import { FormProvider, useForm } from "react-hook-form";
import { useAdminClient, useFetch } from "../context/auth/AdminClient";
import { useAlerts } from "../components/alert/Alerts";
import { useTranslation } from "react-i18next";
import { useParams } from "react-router-dom";
import { useNavigate } from "react-router-dom-v5-compat";
import { Header } from "./shared/Header";
import { toUserFederation } from "./routes/UserFederation";

export default function UserFederationKerberosSettings() {
  const { t } = useTranslation("user-federation");
  const form = useForm<ComponentRepresentation>({ mode: "onChange" });
  const navigate = useNavigate();
  const { adminClient } = useAdminClient();
  const { realm } = useRealm();

  const { id } = useParams<{ id?: string }>();

  const { addAlert, addError } = useAlerts();

  useFetch(
    async () => {
      if (id) {
        return adminClient.components.findOne({ id });
      }
    },
    (fetchedComponent) => {
      if (fetchedComponent) {
        setupForm(fetchedComponent);
      } else if (id) {
        throw new Error(t("common:notFound"));
      }
    },
    []
  );

  const setupForm = (component: ComponentRepresentation) => {
    form.reset({ ...component });
  };

  const save = async (component: ComponentRepresentation) => {
    try {
      if (!id) {
        await adminClient.components.create(component);
        navigate(`/${realm}/user-federation`);
      } else {
        await adminClient.components.update({ id }, component);
      }
      setupForm(component as ComponentRepresentation);
      addAlert(t(!id ? "createSuccess" : "saveSuccess"), AlertVariant.success);
    } catch (error) {
      addError(`user-federation:${!id ? "createError" : "saveError"}`, error);
    }
  };

  return (
    <>
      <FormProvider {...form}>
        <Header provider="Kerberos" save={() => form.handleSubmit(save)()} />
      </FormProvider>
      <PageSection variant="light">
        <KerberosSettingsRequired form={form} showSectionHeading />
      </PageSection>
      <PageSection variant="light" isFilled>
        <SettingsCache form={form} showSectionHeading />
        <Form onSubmit={form.handleSubmit(save)}>
          <ActionGroup>
            <Button
              isDisabled={!form.formState.isDirty}
              variant="primary"
              type="submit"
              data-testid="kerberos-save"
            >
              {t("common:save")}
            </Button>
            <Button
              variant="link"
              onClick={() => navigate(toUserFederation({ realm }))}
              data-testid="kerberos-cancel"
            >
              {t("common:cancel")}
            </Button>
          </ActionGroup>
        </Form>
      </PageSection>
    </>
  );
}
