import { useState } from "react";
import { useParams } from "react-router-dom";
import { Link, useNavigate } from "react-router-dom-v5-compat";
import { useTranslation } from "react-i18next";
import { Controller, FormProvider, useForm } from "react-hook-form";
import {
  ActionGroup,
  AlertVariant,
  Button,
  ButtonVariant,
  Divider,
  DropdownItem,
  Form,
  PageSection,
  Tab,
  TabTitleText,
  ToolbarItem,
} from "@patternfly/react-core";

import type IdentityProviderRepresentation from "@keycloak/keycloak-admin-client/lib/defs/identityProviderRepresentation";
import { FormAccess } from "../../components/form-access/FormAccess";
import { ScrollForm } from "../../components/scroll-form/ScrollForm";
import { ViewHeader } from "../../components/view-header/ViewHeader";
import { KeycloakSpinner } from "../../components/keycloak-spinner/KeycloakSpinner";
import { useFetch, useAdminClient } from "../../context/auth/AdminClient";
import { GeneralSettings } from "./GeneralSettings";
import { AdvancedSettings } from "./AdvancedSettings";
import { useConfirmDialog } from "../../components/confirm-dialog/ConfirmDialog";
import { useAlerts } from "../../components/alert/Alerts";
import { useRealm } from "../../context/realm-context/RealmContext";
import { KeycloakTabs } from "../../components/keycloak-tabs/KeycloakTabs";
import { ExtendedNonDiscoverySettings } from "./ExtendedNonDiscoverySettings";
import { DiscoverySettings } from "./DiscoverySettings";
import { DescriptorSettings } from "./DescriptorSettings";
import { OIDCGeneralSettings } from "./OIDCGeneralSettings";
import { SamlGeneralSettings } from "./SamlGeneralSettings";
import { OIDCAuthentication } from "./OIDCAuthentication";
import { ReqAuthnConstraints } from "./ReqAuthnConstraintsSettings";
import { KeycloakDataTable } from "../../components/table-toolbar/KeycloakDataTable";
import { ListEmptyState } from "../../components/list-empty-state/ListEmptyState";
import type IdentityProviderMapperRepresentation from "@keycloak/keycloak-admin-client/lib/defs/identityProviderMapperRepresentation";
import { toIdentityProviderAddMapper } from "../routes/AddMapper";
import { toIdentityProviderEditMapper } from "../routes/EditMapper";
import { toIdentityProviders } from "../routes/IdentityProviders";

import { toUpperCase } from "../../util";
import {
  IdentityProviderParams,
  toIdentityProvider,
} from "../routes/IdentityProvider";
import { PermissionsTab } from "../../components/permission-tab/PermissionTab";
import { ExtendedFieldsForm } from "../component/ExtendedFieldsForm";

type HeaderProps = {
  onChange: (value: boolean) => void;
  value: boolean;
  save: () => void;
  toggleDeleteDialog: () => void;
};

type IdPWithMapperAttributes = IdentityProviderMapperRepresentation & {
  name: string;
  category?: string;
  helpText?: string;
  type: string;
  mapperId: string;
};

const Header = ({ onChange, value, save, toggleDeleteDialog }: HeaderProps) => {
  const { t } = useTranslation("identity-providers");
  const { alias: displayName } = useParams<{ alias: string }>();

  const [toggleDisableDialog, DisableConfirm] = useConfirmDialog({
    titleKey: "identity-providers:disableProvider",
    messageKey: t("disableConfirm", { provider: displayName }),
    continueButtonLabel: "common:disable",
    onConfirm: () => {
      onChange(!value);
      save();
    },
  });

  return (
    <>
      <DisableConfirm />
      <ViewHeader
        titleKey={toUpperCase(displayName)}
        divider={false}
        dropdownItems={[
          <DropdownItem key="delete" onClick={() => toggleDeleteDialog()}>
            {t("common:delete")}
          </DropdownItem>,
        ]}
        isEnabled={value}
        onToggle={(value) => {
          if (!value) {
            toggleDisableDialog();
          } else {
            onChange(value);
            save();
          }
        }}
      />
    </>
  );
};

export default function DetailSettings() {
  const { t } = useTranslation("identity-providers");
  const { alias, providerId } = useParams<IdentityProviderParams>();

  const form = useForm<IdentityProviderRepresentation>();
  const { handleSubmit, getValues, reset } = form;
  const [provider, setProvider] = useState<IdentityProviderRepresentation>();
  const [selectedMapper, setSelectedMapper] =
    useState<IdPWithMapperAttributes>();

  const { adminClient } = useAdminClient();
  const { addAlert, addError } = useAlerts();
  const navigate = useNavigate();
  const { realm } = useRealm();
  const [key, setKey] = useState(0);
  const refresh = () => setKey(key + 1);

  const MapperLink = ({ name, mapperId }: IdPWithMapperAttributes) => (
    <Link
      to={toIdentityProviderEditMapper({
        realm,
        alias,
        providerId: provider?.providerId!,
        id: mapperId,
      })}
    >
      {name}
    </Link>
  );

  useFetch(
    () => adminClient.identityProviders.findOne({ alias }),
    (fetchedProvider) => {
      if (!fetchedProvider) {
        throw new Error(t("common:notFound"));
      }

      reset(fetchedProvider);
      setProvider(fetchedProvider);

      if (fetchedProvider.config!.authnContextClassRefs) {
        form.setValue(
          "config.authnContextClassRefs",
          JSON.parse(fetchedProvider.config?.authnContextClassRefs)
        );
      }

      if (fetchedProvider.config!.authnContextDeclRefs) {
        form.setValue(
          "config.authnContextDeclRefs",
          JSON.parse(fetchedProvider.config?.authnContextDeclRefs)
        );
      }
    },
    []
  );

  const save = async (savedProvider?: IdentityProviderRepresentation) => {
    const p = savedProvider || getValues();
    if (p.config?.authnContextClassRefs)
      p.config.authnContextClassRefs = JSON.stringify(
        p.config.authnContextClassRefs
      );
    if (p.config?.authnContextDeclRefs)
      p.config.authnContextDeclRefs = JSON.stringify(
        p.config.authnContextDeclRefs
      );

    try {
      await adminClient.identityProviders.update(
        { alias },
        {
          ...p,
          config: { ...provider?.config, ...p.config },
          alias,
          providerId,
        }
      );
      addAlert(t("updateSuccess"), AlertVariant.success);
    } catch (error) {
      addError("identity-providers:updateError", error);
    }
  };

  const [toggleDeleteDialog, DeleteConfirm] = useConfirmDialog({
    titleKey: "identity-providers:deleteProvider",
    messageKey: t("identity-providers:deleteConfirm", { provider: alias }),
    continueButtonLabel: "common:delete",
    continueButtonVariant: ButtonVariant.danger,
    onConfirm: async () => {
      try {
        await adminClient.identityProviders.del({ alias: alias });
        addAlert(t("deletedSuccess"), AlertVariant.success);
        navigate(toIdentityProviders({ realm }));
      } catch (error) {
        addError("identity-providers:deleteErrorError", error);
      }
    },
  });

  const [toggleDeleteMapperDialog, DeleteMapperConfirm] = useConfirmDialog({
    titleKey: "identity-providers:deleteProviderMapper",
    messageKey: t("identity-providers:deleteMapperConfirm", {
      mapper: selectedMapper?.name,
    }),
    continueButtonLabel: "common:delete",
    continueButtonVariant: ButtonVariant.danger,
    onConfirm: async () => {
      try {
        await adminClient.identityProviders.delMapper({
          alias: alias,
          id: selectedMapper?.mapperId!,
        });
        addAlert(t("deleteMapperSuccess"), AlertVariant.success);
        refresh();
        navigate(
          toIdentityProvider({ providerId, alias, tab: "mappers", realm })
        );
      } catch (error) {
        addError("identity-providers:deleteErrorError", error);
      }
    },
  });

  if (!provider) {
    return <KeycloakSpinner />;
  }

  const isOIDC = provider.providerId!.includes("oidc");
  const isSAML = provider.providerId!.includes("saml");

  const loader = async () => {
    const [loaderMappers, loaderMapperTypes] = await Promise.all([
      adminClient.identityProviders.findMappers({ alias }),
      adminClient.identityProviders.findMapperTypes({ alias }),
    ]);

    const components = loaderMappers.map((loaderMapper) => {
      const mapperType = Object.values(loaderMapperTypes).find(
        (loaderMapperType) =>
          loaderMapper.identityProviderMapper! === loaderMapperType.id!
      );

      const result: IdPWithMapperAttributes = {
        ...mapperType,
        name: loaderMapper.name!,
        type: mapperType?.name!,
        mapperId: loaderMapper.id!,
      };

      return result;
    });

    return components;
  };

  const sections = [
    {
      title: t("generalSettings"),
      panel: (
        <FormAccess
          role="manage-identity-providers"
          isHorizontal
          onSubmit={handleSubmit(save)}
        >
          {!isOIDC && !isSAML && (
            <>
              <GeneralSettings create={false} id={alias} />
              <ExtendedFieldsForm providerId={alias} />
            </>
          )}
          {isOIDC && <OIDCGeneralSettings id={alias} />}
          {isSAML && <SamlGeneralSettings id={alias} isAliasReadonly />}
        </FormAccess>
      ),
    },
    {
      title: t("oidcSettings"),
      isHidden: !isOIDC,
      panel: (
        <>
          <DiscoverySettings readOnly={false} />
          <Form isHorizontal className="pf-u-py-lg">
            <Divider />
            <OIDCAuthentication create={false} />
          </Form>
          <ExtendedNonDiscoverySettings />
        </>
      ),
    },
    {
      title: t("samlSettings"),
      isHidden: !isSAML,
      panel: <DescriptorSettings readOnly={false} />,
    },
    {
      title: t("reqAuthnConstraints"),
      isHidden: !isSAML,
      panel: (
        <FormAccess
          role="manage-identity-providers"
          isHorizontal
          onSubmit={handleSubmit(save)}
        >
          <ReqAuthnConstraints />
        </FormAccess>
      ),
    },
    {
      title: t("advancedSettings"),
      panel: (
        <FormAccess
          role="manage-identity-providers"
          isHorizontal
          onSubmit={handleSubmit(save)}
        >
          <AdvancedSettings isOIDC={isOIDC!} isSAML={isSAML!} />

          <ActionGroup className="keycloak__form_actions">
            <Button data-testid={"save"} type="submit">
              {t("common:save")}
            </Button>
            <Button
              data-testid={"revert"}
              variant="link"
              onClick={() => {
                reset();
              }}
            >
              {t("common:revert")}
            </Button>
          </ActionGroup>
        </FormAccess>
      ),
    },
  ];

  return (
    <FormProvider {...form}>
      <DeleteConfirm />
      <DeleteMapperConfirm />
      <Controller
        name="enabled"
        control={form.control}
        defaultValue={true}
        render={({ onChange, value }) => (
          <Header
            value={value}
            onChange={onChange}
            save={save}
            toggleDeleteDialog={toggleDeleteDialog}
          />
        )}
      />

      <PageSection variant="light" className="pf-u-p-0">
        <KeycloakTabs isBox>
          <Tab
            id="settings"
            eventKey="settings"
            title={<TabTitleText>{t("common:settings")}</TabTitleText>}
          >
            <ScrollForm className="pf-u-px-lg" sections={sections} />
          </Tab>
          <Tab
            id="mappers"
            data-testid="mappers-tab"
            eventKey="mappers"
            title={<TabTitleText>{t("common:mappers")}</TabTitleText>}
          >
            <KeycloakDataTable
              emptyState={
                <ListEmptyState
                  message={t("identity-providers:noMappers")}
                  instructions={t("identity-providers:noMappersInstructions")}
                  primaryActionText={t("identity-providers:addMapper")}
                  onPrimaryAction={() =>
                    navigate(
                      toIdentityProviderAddMapper({
                        realm,
                        alias: alias!,
                        providerId: provider.providerId!,
                        tab: "mappers",
                      })
                    )
                  }
                />
              }
              loader={loader}
              key={key}
              ariaLabelKey="identity-providers:mappersList"
              searchPlaceholderKey="identity-providers:searchForMapper"
              toolbarItem={
                <ToolbarItem>
                  <Button
                    id="add-mapper-button"
                    component={(props) => (
                      <Link
                        {...props}
                        to={toIdentityProviderAddMapper({
                          realm,
                          alias: alias!,
                          providerId: provider.providerId!,
                          tab: "mappers",
                        })}
                      />
                    )}
                    data-testid="addMapper"
                  >
                    {t("addMapper")}
                  </Button>
                </ToolbarItem>
              }
              columns={[
                {
                  name: "name",
                  displayKey: "common:name",
                  cellRenderer: MapperLink,
                },
                {
                  name: "category",
                  displayKey: "common:category",
                },
                {
                  name: "type",
                  displayKey: "common:type",
                },
              ]}
              actions={[
                {
                  title: t("common:delete"),
                  onRowClick: (mapper) => {
                    setSelectedMapper(mapper);
                    toggleDeleteMapperDialog();
                  },
                },
              ]}
            />
          </Tab>
          <Tab
            id="permissions"
            data-testid="permissionsTab"
            eventKey="permissions"
            title={<TabTitleText>{t("common:permissions")}</TabTitleText>}
          >
            <PermissionsTab id={alias} type="identityProviders" />
          </Tab>
        </KeycloakTabs>
      </PageSection>
    </FormProvider>
  );
}
