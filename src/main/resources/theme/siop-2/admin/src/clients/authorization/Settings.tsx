import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Controller, FormProvider, useForm } from "react-hook-form";
import {
  AlertVariant,
  Button,
  Divider,
  FormGroup,
  PageSection,
  Radio,
  Switch,
} from "@patternfly/react-core";

import type ResourceServerRepresentation from "@keycloak/keycloak-admin-client/lib/defs/resourceServerRepresentation";
import { KeycloakSpinner } from "../../components/keycloak-spinner/KeycloakSpinner";
import { useAdminClient, useFetch } from "../../context/auth/AdminClient";
import { FormAccess } from "../../components/form-access/FormAccess";
import { HelpItem } from "../../components/help-enabler/HelpItem";
import { SaveReset } from "../advanced/SaveReset";
import { ImportDialog } from "./ImportDialog";
import useToggle from "../../utils/useToggle";
import { useAlerts } from "../../components/alert/Alerts";
import { DecisionStrategySelect } from "./DecisionStragegySelect";

const POLICY_ENFORCEMENT_MODES = [
  "ENFORCING",
  "PERMISSIVE",
  "DISABLED",
] as const;

export const AuthorizationSettings = ({ clientId }: { clientId: string }) => {
  const { t } = useTranslation("clients");
  const [resource, setResource] = useState<ResourceServerRepresentation>();
  const [importDialog, toggleImportDialog] = useToggle();

  const form = useForm<ResourceServerRepresentation>({});
  const { control, reset, handleSubmit } = form;

  const { adminClient } = useAdminClient();
  const { addAlert, addError } = useAlerts();

  useFetch(
    () => adminClient.clients.getResourceServer({ id: clientId }),
    (resource) => {
      setResource(resource);
      reset(resource);
    },
    []
  );

  const importResource = async (value: ResourceServerRepresentation) => {
    try {
      await adminClient.clients.importResource({ id: clientId }, value);
      addAlert(t("importResourceSuccess"), AlertVariant.success);
      reset({ ...value });
    } catch (error) {
      addError("clients:importResourceError", error);
    }
  };

  const save = async (resource: ResourceServerRepresentation) => {
    try {
      await adminClient.clients.updateResourceServer(
        { id: clientId },
        resource
      );
      addAlert(t("updateResourceSuccess"), AlertVariant.success);
    } catch (error) {
      addError("clients:resourceSaveError", error);
    }
  };

  if (!resource) {
    return <KeycloakSpinner />;
  }

  return (
    <PageSection variant="light">
      {importDialog && (
        <ImportDialog
          onConfirm={importResource}
          closeDialog={toggleImportDialog}
        />
      )}
      <FormAccess role="view-clients" isHorizontal>
        <FormGroup
          label={t("import")}
          fieldId="import"
          labelIcon={
            <HelpItem
              helpText="clients-help:import"
              fieldLabelId="clients:import"
            />
          }
        >
          <Button variant="secondary" onClick={toggleImportDialog}>
            {t("import")}
          </Button>
        </FormGroup>
        <Divider />
        <FormGroup
          label={t("policyEnforcementMode")}
          labelIcon={
            <HelpItem
              helpText="clients-help:policyEnforcementMode"
              fieldLabelId="clients:policyEnforcementMode"
            />
          }
          fieldId="policyEnforcementMode"
          hasNoPaddingTop
        >
          <Controller
            name="policyEnforcementMode"
            data-testid="policyEnforcementMode"
            defaultValue={POLICY_ENFORCEMENT_MODES[0]}
            control={control}
            render={({ onChange, value }) => (
              <>
                {POLICY_ENFORCEMENT_MODES.map((mode) => (
                  <Radio
                    id={mode}
                    key={mode}
                    data-testid={mode}
                    isChecked={value === mode}
                    name="policyEnforcementMode"
                    onChange={() => onChange(mode)}
                    label={t(`policyEnforcementModes.${mode}`)}
                    className="pf-u-mb-md"
                  />
                ))}
              </>
            )}
          />
        </FormGroup>
        <FormProvider {...form}>
          <DecisionStrategySelect isLimited />
        </FormProvider>
        <FormGroup
          hasNoPaddingTop
          label={t("allowRemoteResourceManagement")}
          fieldId="allowRemoteResourceManagement"
          labelIcon={
            <HelpItem
              helpText="clients-help:allowRemoteResourceManagement"
              fieldLabelId="clients:allowRemoteResourceManagement"
            />
          }
        >
          <Controller
            name="allowRemoteResourceManagement"
            data-testid="allowRemoteResourceManagement"
            defaultValue={false}
            control={control}
            render={({ onChange, value }) => (
              <Switch
                id="allowRemoteResourceManagement"
                label={t("common:on")}
                labelOff={t("common:off")}
                isChecked={value}
                onChange={onChange}
                aria-label={t("allowRemoteResourceManagement")}
              />
            )}
          />
        </FormGroup>
        <SaveReset
          name="authenticationSettings"
          save={() => handleSubmit(save)()}
          reset={() => reset(resource)}
          isActive
        />
      </FormAccess>
    </PageSection>
  );
};
