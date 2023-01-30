import { useState } from "react";
import { Link } from "react-router-dom-v5-compat";
import { useNavigate } from "react-router-dom-v5-compat";
import { useTranslation } from "react-i18next";
import {
  Alert,
  AlertVariant,
  ButtonVariant,
  DescriptionList,
  Dropdown,
  DropdownItem,
  DropdownSeparator,
  DropdownToggle,
  PageSection,
  ToolbarItem,
} from "@patternfly/react-core";
import {
  ExpandableRowContent,
  TableComposable,
  Tbody,
  Td,
  Th,
  Thead,
  Tr,
} from "@patternfly/react-table";

import type PolicyRepresentation from "@keycloak/keycloak-admin-client/lib/defs/policyRepresentation";
import type PolicyProviderRepresentation from "@keycloak/keycloak-admin-client/lib/defs/policyProviderRepresentation";
import { KeycloakSpinner } from "../../components/keycloak-spinner/KeycloakSpinner";
import { useConfirmDialog } from "../../components/confirm-dialog/ConfirmDialog";
import { PaginatingTableToolbar } from "../../components/table-toolbar/PaginatingTableToolbar";
import { useAlerts } from "../../components/alert/Alerts";
import { useAdminClient, useFetch } from "../../context/auth/AdminClient";
import useToggle from "../../utils/useToggle";
import { useRealm } from "../../context/realm-context/RealmContext";
import { SearchDropdown, SearchForm } from "./SearchDropdown";
import { MoreLabel } from "./MoreLabel";
import { DetailDescriptionLink } from "./DetailDescription";
import { EmptyPermissionsState } from "./EmptyPermissionsState";
import { toNewPermission } from "../routes/NewPermission";
import { toPermissionDetails } from "../routes/PermissionDetails";
import { ListEmptyState } from "../../components/list-empty-state/ListEmptyState";
import { toPolicyDetails } from "../routes/PolicyDetails";

import "./permissions.css";

type PermissionsProps = {
  clientId: string;
};

type ExpandablePolicyRepresentation = PolicyRepresentation & {
  associatedPolicies?: PolicyRepresentation[];
  isExpanded: boolean;
};

export const AuthorizationPermissions = ({ clientId }: PermissionsProps) => {
  const { t } = useTranslation("clients");
  const navigate = useNavigate();
  const { adminClient } = useAdminClient();
  const { addAlert, addError } = useAlerts();
  const { realm } = useRealm();

  const [permissions, setPermissions] =
    useState<ExpandablePolicyRepresentation[]>();
  const [selectedPermission, setSelectedPermission] =
    useState<PolicyRepresentation>();
  const [policyProviders, setPolicyProviders] =
    useState<PolicyProviderRepresentation[]>();
  const [disabledCreate, setDisabledCreate] = useState<{
    resources: boolean;
    scopes: boolean;
  }>();
  const [createOpen, toggleCreate] = useToggle();
  const [search, setSearch] = useState<SearchForm>({});

  const [key, setKey] = useState(0);
  const refresh = () => setKey(key + 1);

  const [max, setMax] = useState(10);
  const [first, setFirst] = useState(0);

  const AssociatedPoliciesRenderer = ({
    row,
  }: {
    row: ExpandablePolicyRepresentation;
  }) => {
    return (
      <>
        {row.associatedPolicies?.[0]?.name}{" "}
        <MoreLabel array={row.associatedPolicies} />
      </>
    );
  };

  useFetch(
    async () => {
      const permissions = await adminClient.clients.findPermissions({
        first,
        max: max + 1,
        id: clientId,
        ...search,
      });

      return await Promise.all(
        permissions.map(async (permission) => {
          const associatedPolicies =
            await adminClient.clients.getAssociatedPolicies({
              id: clientId,
              permissionId: permission.id!,
            });

          return {
            ...permission,
            associatedPolicies,
            isExpanded: false,
          };
        })
      );
    },
    setPermissions,
    [key, search, first, max]
  );

  useFetch(
    async () => {
      const params = {
        first: 0,
        max: 1,
      };
      const [policies, resources, scopes] = await Promise.all([
        adminClient.clients.listPolicyProviders({
          id: clientId,
        }),
        adminClient.clients.listResources({ ...params, id: clientId }),
        adminClient.clients.listAllScopes({ ...params, id: clientId }),
      ]);
      return {
        policies: policies.filter(
          (p) => p.type === "resource" || p.type === "scope"
        ),
        resources: resources.length !== 1,
        scopes: scopes.length !== 1,
      };
    },
    ({ policies, resources, scopes }) => {
      setPolicyProviders(policies);
      setDisabledCreate({ resources, scopes });
    },
    []
  );

  const [toggleDeleteDialog, DeleteConfirm] = useConfirmDialog({
    titleKey: "clients:deletePermission",
    messageKey: t("deletePermissionConfirm", {
      permission: selectedPermission?.name,
    }),
    continueButtonVariant: ButtonVariant.danger,
    continueButtonLabel: "clients:confirm",
    onConfirm: async () => {
      try {
        await adminClient.clients.delPermission({
          id: clientId,
          type: selectedPermission?.type!,
          permissionId: selectedPermission?.id!,
        });
        addAlert(t("permissionDeletedSuccess"), AlertVariant.success);
        refresh();
      } catch (error) {
        addError("clients:permissionDeletedError", error);
      }
    },
  });

  if (!permissions) {
    return <KeycloakSpinner />;
  }

  const noData = permissions.length === 0;
  const searching = Object.keys(search).length !== 0;
  return (
    <PageSection variant="light" className="pf-u-p-0">
      <DeleteConfirm />
      {(!noData || searching) && (
        <PaginatingTableToolbar
          count={permissions.length}
          first={first}
          max={max}
          onNextClick={setFirst}
          onPreviousClick={setFirst}
          onPerPageSelect={(first, max) => {
            setFirst(first);
            setMax(max);
          }}
          toolbarItem={
            <>
              <ToolbarItem>
                <SearchDropdown
                  types={policyProviders}
                  search={search}
                  onSearch={setSearch}
                />
              </ToolbarItem>
              <ToolbarItem>
                <Dropdown
                  toggle={
                    <DropdownToggle
                      onToggle={toggleCreate}
                      isPrimary
                      data-testid="permissionCreateDropdown"
                    >
                      {t("createPermission")}
                    </DropdownToggle>
                  }
                  isOpen={createOpen}
                  dropdownItems={[
                    <DropdownItem
                      data-testid="create-resource"
                      key="createResourceBasedPermission"
                      isDisabled={disabledCreate?.resources}
                      component="button"
                      onClick={() =>
                        navigate(
                          toNewPermission({
                            realm,
                            id: clientId,
                            permissionType: "resource",
                          })
                        )
                      }
                    >
                      {t("createResourceBasedPermission")}
                    </DropdownItem>,
                    <DropdownSeparator key="separator" />,
                    <DropdownItem
                      data-testid="create-scope"
                      key="createScopeBasedPermission"
                      isDisabled={disabledCreate?.scopes}
                      component="button"
                      onClick={() =>
                        navigate(
                          toNewPermission({
                            realm,
                            id: clientId,
                            permissionType: "scope",
                          })
                        )
                      }
                    >
                      {t("createScopeBasedPermission")}
                      {disabledCreate?.scopes && (
                        <Alert
                          className="pf-u-mt-sm"
                          variant="warning"
                          isInline
                          isPlain
                          title={t("noScopeCreateHint")}
                        />
                      )}
                    </DropdownItem>,
                  ]}
                />
              </ToolbarItem>
            </>
          }
        >
          {!noData && (
            <TableComposable aria-label={t("resources")} variant="compact">
              <Thead>
                <Tr>
                  <Th />
                  <Th>{t("common:name")}</Th>
                  <Th>{t("common:type")}</Th>
                  <Th>{t("associatedPolicy")}</Th>
                  <Th>{t("common:description")}</Th>
                  <Th />
                </Tr>
              </Thead>
              {permissions.map((permission, rowIndex) => (
                <Tbody key={permission.id} isExpanded={permission.isExpanded}>
                  <Tr>
                    <Td
                      expand={{
                        rowIndex,
                        isExpanded: permission.isExpanded,
                        onToggle: (_, rowIndex) => {
                          const rows = permissions.map((p, index) =>
                            index === rowIndex
                              ? { ...p, isExpanded: !p.isExpanded }
                              : p
                          );
                          setPermissions(rows);
                        },
                      }}
                    />
                    <Td data-testid={`name-column-${permission.name}`}>
                      <Link
                        to={toPermissionDetails({
                          realm,
                          id: clientId,
                          permissionType: permission.type!,
                          permissionId: permission.id!,
                        })}
                      >
                        {permission.name}
                      </Link>
                    </Td>
                    <Td>
                      {
                        policyProviders?.find((p) => p.type === permission.type)
                          ?.name
                      }
                    </Td>
                    <Td>
                      <AssociatedPoliciesRenderer row={permission} />
                    </Td>
                    <Td>{permission.description}</Td>
                    <Td
                      actions={{
                        items: [
                          {
                            title: t("common:delete"),
                            onClick: async () => {
                              setSelectedPermission(permission);
                              toggleDeleteDialog();
                            },
                          },
                        ],
                      }}
                    ></Td>
                  </Tr>
                  <Tr
                    key={`child-${permission.id}`}
                    isExpanded={permission.isExpanded}
                  >
                    <Td />
                    <Td colSpan={5}>
                      <ExpandableRowContent>
                        {permission.isExpanded && (
                          <DescriptionList
                            isHorizontal
                            className="keycloak_resource_details"
                          >
                            <DetailDescriptionLink
                              name="associatedPolicy"
                              array={permission.associatedPolicies}
                              convert={(p) => p.name!}
                              link={(p) =>
                                toPolicyDetails({
                                  id: clientId,
                                  realm,
                                  policyId: p.id!,
                                  policyType: p.type!,
                                })
                              }
                            />
                          </DescriptionList>
                        )}
                      </ExpandableRowContent>
                    </Td>
                  </Tr>
                </Tbody>
              ))}
            </TableComposable>
          )}
        </PaginatingTableToolbar>
      )}
      {noData && !searching && (
        <EmptyPermissionsState
          clientId={clientId}
          isResourceEnabled={disabledCreate?.resources}
          isScopeEnabled={disabledCreate?.scopes}
        />
      )}
      {noData && searching && (
        <ListEmptyState
          isSearchVariant
          message={t("common:noSearchResults")}
          instructions={t("common:noSearchResultsInstructions")}
        />
      )}
    </PageSection>
  );
};
