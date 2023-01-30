import { useState } from "react";
import { Link } from "react-router-dom-v5-compat";
import { useTranslation } from "react-i18next";
import {
  AlertVariant,
  Button,
  ButtonVariant,
  Dropdown,
  DropdownItem,
  KebabToggle,
  ToolbarItem,
} from "@patternfly/react-core";
import type ClientScopeRepresentation from "@keycloak/keycloak-admin-client/lib/defs/clientScopeRepresentation";

import { useAdminClient } from "../../context/auth/AdminClient";
import { ListEmptyState } from "../../components/list-empty-state/ListEmptyState";
import { AddScopeDialog } from "./AddScopeDialog";
import {
  ClientScope,
  CellDropdown,
  AllClientScopes,
  AllClientScopeType,
  changeClientScope,
  addClientScope,
  removeClientScope,
} from "../../components/client-scope/ClientScopeTypes";
import { useAlerts } from "../../components/alert/Alerts";
import { KeycloakDataTable } from "../../components/table-toolbar/KeycloakDataTable";
import {
  nameFilter,
  SearchDropdown,
  SearchToolbar,
  SearchType,
  typeFilter,
} from "../../client-scopes/details/SearchFilter";
import { ChangeTypeDropdown } from "../../client-scopes/ChangeTypeDropdown";

import { toDedicatedScope } from "../routes/DedicatedScopeDetails";
import { useRealm } from "../../context/realm-context/RealmContext";
import useLocaleSort, { mapByKey } from "../../utils/useLocaleSort";
import { useAccess } from "../../context/access/Access";
import { useConfirmDialog } from "../../components/confirm-dialog/ConfirmDialog";

import "./client-scopes.css";

export type ClientScopesProps = {
  clientId: string;
  protocol: string;
  clientName: string;
  fineGrainedAccess?: boolean;
};

export type Row = ClientScopeRepresentation & {
  type: AllClientScopeType;
  description?: string;
};

const DEDICATED_ROW = "dedicated";

export const ClientScopes = ({
  clientId,
  protocol,
  clientName,
  fineGrainedAccess,
}: ClientScopesProps) => {
  const { t } = useTranslation("clients");
  const { adminClient } = useAdminClient();
  const { addAlert, addError } = useAlerts();
  const { realm } = useRealm();
  const localeSort = useLocaleSort();

  const [searchType, setSearchType] = useState<SearchType>("name");

  const [searchTypeType, setSearchTypeType] = useState<AllClientScopes>(
    AllClientScopes.none
  );

  const [addDialogOpen, setAddDialogOpen] = useState(false);

  const [rest, setRest] = useState<ClientScopeRepresentation[]>();
  const [selectedRows, setSelectedRowState] = useState<Row[]>([]);
  const setSelectedRows = (rows: Row[]) =>
    setSelectedRowState(rows.filter(({ id }) => id !== DEDICATED_ROW));

  const [key, setKey] = useState(0);
  const refresh = () => setKey(key + 1);
  const isDedicatedRow = (value: Row) => value.id === DEDICATED_ROW;

  const { hasAccess } = useAccess();
  const isManager = hasAccess("manage-clients") || fineGrainedAccess;

  const loader = async (first?: number, max?: number, search?: string) => {
    const defaultClientScopes =
      await adminClient.clients.listDefaultClientScopes({ id: clientId });
    const optionalClientScopes =
      await adminClient.clients.listOptionalClientScopes({ id: clientId });
    const clientScopes = await adminClient.clientScopes.find();

    const find = (id: string) =>
      clientScopes.find((clientScope) => id === clientScope.id);

    const optional = optionalClientScopes.map((c) => {
      const scope = find(c.id!);
      const row: Row = {
        ...c,
        type: ClientScope.optional,
        description: scope?.description,
      };
      return row;
    });

    const defaultScopes = defaultClientScopes.map((c) => {
      const scope = find(c.id!);
      const row: Row = {
        ...c,
        type: ClientScope.default,
        description: scope?.description,
      };
      return row;
    });

    const rows = [...optional, ...defaultScopes];
    const names = rows.map((row) => row.name);
    setRest(
      clientScopes
        .filter((scope) => !names.includes(scope.name))
        .filter((scope) => scope.protocol === protocol)
    );

    const filter =
      searchType === "name" ? nameFilter(search) : typeFilter(searchTypeType);
    const firstNum = Number(first);
    const page = localeSort(rows.filter(filter), mapByKey("name")).slice(
      firstNum,
      firstNum + Number(max)
    );
    if (firstNum === 0 && isManager) {
      return [
        {
          id: DEDICATED_ROW,
          name: t("dedicatedScopeName", { clientName }),
          type: AllClientScopes.none,
          description: t("dedicatedScopeDescription"),
        },
        ...page,
      ];
    }
    return page;
  };

  const TypeSelector = (scope: Row) => (
    <CellDropdown
      isDisabled={isDedicatedRow(scope) || !isManager}
      clientScope={scope}
      type={scope.type}
      onSelect={async (value) => {
        try {
          await changeClientScope(
            adminClient,
            clientId,
            scope,
            scope.type,
            value as ClientScope
          );
          addAlert(t("clientScopeSuccess"), AlertVariant.success);
          refresh();
        } catch (error) {
          addError("clients:clientScopeError", error);
        }
      }}
    />
  );

  const [toggleDeleteDialog, DeleteConfirm] = useConfirmDialog({
    titleKey: t("client-scopes:deleteClientScope", {
      count: selectedRows.length,
      name: selectedRows[0]?.name,
    }),
    messageKey: "client-scopes:deleteConfirm",
    continueButtonLabel: "common:delete",
    continueButtonVariant: ButtonVariant.danger,
    onConfirm: async () => {
      try {
        await removeClientScope(
          adminClient,
          clientId,
          selectedRows[0],
          selectedRows[0].type as ClientScope
        );
        addAlert(t("clientScopeRemoveSuccess"), AlertVariant.success);
        refresh();
      } catch (error) {
        addError("clients:clientScopeRemoveError", error);
      }
    },
  });

  const ManagerToolbarItems = () => {
    const [kebabOpen, setKebabOpen] = useState(false);

    if (!isManager) return <span />;

    return (
      <>
        <DeleteConfirm />
        <ToolbarItem>
          <Button onClick={() => setAddDialogOpen(true)}>
            {t("addClientScope")}
          </Button>
        </ToolbarItem>
        <ToolbarItem>
          <ChangeTypeDropdown
            clientId={clientId}
            selectedRows={selectedRows}
            refresh={refresh}
          />
        </ToolbarItem>
        <ToolbarItem>
          <Dropdown
            toggle={<KebabToggle onToggle={() => setKebabOpen(!kebabOpen)} />}
            isOpen={kebabOpen}
            isPlain
            dropdownItems={[
              <DropdownItem
                key="deleteAll"
                isDisabled={selectedRows.length === 0}
                onClick={async () => {
                  try {
                    await Promise.all(
                      selectedRows.map((row) =>
                        removeClientScope(
                          adminClient,
                          clientId,
                          { ...row },
                          row.type as ClientScope
                        )
                      )
                    );

                    setKebabOpen(false);
                    setSelectedRows([]);
                    addAlert(t("clients:clientScopeRemoveSuccess"));
                    refresh();
                  } catch (error) {
                    addError("clients:clientScopeRemoveError", error);
                  }
                }}
              >
                {t("common:remove")}
              </DropdownItem>,
            ]}
          />
        </ToolbarItem>
      </>
    );
  };

  return (
    <>
      {rest && (
        <AddScopeDialog
          clientScopes={rest}
          clientName={clientName!}
          open={addDialogOpen}
          toggleDialog={() => setAddDialogOpen(!addDialogOpen)}
          onAdd={async (scopes) => {
            try {
              await Promise.all(
                scopes.map(
                  async (scope) =>
                    await addClientScope(
                      adminClient,
                      clientId,
                      scope.scope,
                      scope.type!
                    )
                )
              );
              addAlert(t("clientScopeSuccess"), AlertVariant.success);
              refresh();
            } catch (error) {
              addError("clients:clientScopeError", error);
            }
          }}
        />
      )}

      <KeycloakDataTable
        key={key}
        loader={loader}
        ariaLabelKey="clients:clientScopeList"
        searchPlaceholderKey={
          searchType === "name" ? "clients:searchByName" : undefined
        }
        canSelectAll
        isPaginated
        isSearching={searchType === "type"}
        onSelect={(rows) => setSelectedRows([...rows])}
        searchTypeComponent={
          <SearchDropdown
            searchType={searchType}
            onSelect={(searchType) => setSearchType(searchType)}
          />
        }
        toolbarItem={
          <>
            <SearchToolbar
              searchType={searchType}
              type={searchTypeType}
              onSelect={(searchType) => setSearchType(searchType)}
              onType={(value) => {
                setSearchTypeType(value);
                refresh();
              }}
            />
            <ManagerToolbarItems />
          </>
        }
        columns={[
          {
            name: "name",
            displayKey: "clients:assignedClientScope",
            cellRenderer: (row) => {
              if (isDedicatedRow(row)) {
                return (
                  <Link to={toDedicatedScope({ realm, clientId })}>
                    {row.name}
                  </Link>
                );
              }
              return row.name;
            },
          },
          {
            name: "type",
            displayKey: "clients:assignedType",
            cellRenderer: TypeSelector,
          },
          { name: "description" },
        ]}
        actions={
          isManager
            ? [
                {
                  title: t("common:remove"),
                  onRowClick: async (row) => {
                    setSelectedRows([row]);
                    toggleDeleteDialog();
                    return true;
                  },
                },
              ]
            : []
        }
        emptyState={
          <ListEmptyState
            message={t("clients:emptyClientScopes")}
            instructions={t("clients:emptyClientScopesInstructions")}
            primaryActionText={t("clients:emptyClientScopesPrimaryAction")}
            onPrimaryAction={() => setAddDialogOpen(true)}
          />
        }
      />
    </>
  );
};
