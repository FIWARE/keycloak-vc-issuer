import { useState } from "react";
import { useParams } from "react-router-dom";
import { Link, useNavigate } from "react-router-dom-v5-compat";
import { useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";
import {
  ActionGroup,
  AlertVariant,
  Button,
  ButtonVariant,
  DropdownItem,
  FormGroup,
  PageSection,
  ValidatedOptions,
} from "@patternfly/react-core";

import type ScopeRepresentation from "@keycloak/keycloak-admin-client/lib/defs/scopeRepresentation";
import type { ScopeDetailsParams } from "../routes/Scope";
import { FormAccess } from "../../components/form-access/FormAccess";
import { HelpItem } from "../../components/help-enabler/HelpItem";
import { ViewHeader } from "../../components/view-header/ViewHeader";
import { toAuthorizationTab } from "../routes/AuthenticationTab";
import { useAdminClient, useFetch } from "../../context/auth/AdminClient";
import { useAlerts } from "../../components/alert/Alerts";
import { KeycloakTextInput } from "../../components/keycloak-text-input/KeycloakTextInput";
import useToggle from "../../utils/useToggle";
import { DeleteScopeDialog } from "./DeleteScopeDialog";

export default function ScopeDetails() {
  const { t } = useTranslation("clients");
  const { id, scopeId, realm } = useParams<ScopeDetailsParams>();
  const navigate = useNavigate();

  const { adminClient } = useAdminClient();
  const { addAlert, addError } = useAlerts();

  const [deleteDialog, toggleDeleteDialog] = useToggle();
  const [scope, setScope] = useState<ScopeRepresentation>();
  const {
    register,
    reset,
    handleSubmit,
    formState: { errors },
  } = useForm<ScopeRepresentation>({
    mode: "onChange",
  });

  useFetch(
    async () => {
      if (scopeId) {
        const scope = await adminClient.clients.getAuthorizationScope({
          id,
          scopeId,
        });
        if (!scope) {
          throw new Error(t("common:notFound"));
        }
        return scope;
      }
    },
    (scope) => {
      setScope(scope);
      reset({ ...scope });
    },
    []
  );

  const save = async (scope: ScopeRepresentation) => {
    try {
      if (scopeId) {
        await adminClient.clients.updateAuthorizationScope(
          { id, scopeId },
          scope
        );
        setScope(scope);
      } else {
        await adminClient.clients.createAuthorizationScope(
          { id },
          {
            name: scope.name!,
            displayName: scope.displayName,
            iconUri: scope.iconUri,
          }
        );
        navigate(toAuthorizationTab({ realm, clientId: id, tab: "scopes" }));
      }
      addAlert(
        t((scopeId ? "update" : "create") + "ScopeSuccess"),
        AlertVariant.success
      );
    } catch (error) {
      addError("clients:scopeSaveError", error);
    }
  };

  return (
    <>
      <DeleteScopeDialog
        clientId={id}
        open={deleteDialog}
        toggleDialog={toggleDeleteDialog}
        selectedScope={scope}
        refresh={() =>
          navigate(toAuthorizationTab({ realm, clientId: id, tab: "scopes" }))
        }
      />
      <ViewHeader
        titleKey={
          scopeId ? scope?.name! : t("clients:createAuthorizationScope")
        }
        dropdownItems={
          scopeId
            ? [
                <DropdownItem
                  key="delete"
                  data-testid="delete-resource"
                  onClick={() => toggleDeleteDialog()}
                >
                  {t("common:delete")}
                </DropdownItem>,
              ]
            : undefined
        }
      />
      <PageSection variant="light">
        <FormAccess
          isHorizontal
          role="view-clients"
          onSubmit={handleSubmit(save)}
        >
          <FormGroup
            label={t("common:name")}
            fieldId="name"
            labelIcon={
              <HelpItem helpText="clients-help:scopeName" fieldLabelId="name" />
            }
            helperTextInvalid={t("common:required")}
            validated={
              errors.name ? ValidatedOptions.error : ValidatedOptions.default
            }
            isRequired
          >
            <KeycloakTextInput
              id="name"
              name="name"
              ref={register({ required: true })}
              validated={
                errors.name ? ValidatedOptions.error : ValidatedOptions.default
              }
            />
          </FormGroup>
          <FormGroup
            label={t("displayName")}
            fieldId="displayName"
            labelIcon={
              <HelpItem
                helpText="clients-help:scopeDisplayName"
                fieldLabelId="displayName"
              />
            }
          >
            <KeycloakTextInput
              id="displayName"
              name="displayName"
              ref={register}
            />
          </FormGroup>
          <FormGroup
            label={t("iconUri")}
            fieldId="iconUri"
            labelIcon={
              <HelpItem
                helpText="clients-help:iconUri"
                fieldLabelId="clients:iconUri"
              />
            }
          >
            <KeycloakTextInput id="iconUri" name="iconUri" ref={register} />
          </FormGroup>
          <ActionGroup>
            <div className="pf-u-mt-md">
              <Button
                variant={ButtonVariant.primary}
                type="submit"
                data-testid="save"
              >
                {t("common:save")}
              </Button>

              {!scope ? (
                <Button
                  variant="link"
                  data-testid="cancel"
                  component={(props) => (
                    <Link
                      {...props}
                      to={toAuthorizationTab({
                        realm,
                        clientId: id,
                        tab: "scopes",
                      })}
                    ></Link>
                  )}
                >
                  {t("common:cancel")}
                </Button>
              ) : (
                <Button
                  variant="link"
                  data-testid="revert"
                  onClick={() => reset({ ...scope })}
                >
                  {t("common:revert")}
                </Button>
              )}
            </div>
          </ActionGroup>
        </FormAccess>
      </PageSection>
    </>
  );
}
