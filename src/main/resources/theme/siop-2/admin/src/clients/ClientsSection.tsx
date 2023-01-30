import {
  AlertVariant,
  Badge,
  Button,
  ButtonVariant,
  PageSection,
  Tab,
  TabTitleText,
  ToolbarItem,
} from "@patternfly/react-core";
import { cellWidth, IRowData, TableText } from "@patternfly/react-table";
import type ClientRepresentation from "@keycloak/keycloak-admin-client/lib/defs/clientRepresentation";
import type { ClientQuery } from "@keycloak/keycloak-admin-client/lib/resources/clients";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useHistory } from "react-router-dom";
import { Link } from "react-router-dom-v5-compat";
import { useAlerts } from "../components/alert/Alerts";
import { useConfirmDialog } from "../components/confirm-dialog/ConfirmDialog";
import { formattedLinkTableCell } from "../components/external-link/FormattedLink";
import {
  Action,
  KeycloakDataTable,
} from "../components/table-toolbar/KeycloakDataTable";
import { ViewHeader } from "../components/view-header/ViewHeader";
import { useAdminClient } from "../context/auth/AdminClient";
import { useRealm } from "../context/realm-context/RealmContext";
import { emptyFormatter, exportClient } from "../util";
import { convertClientToUrl } from "../utils/client-url";
import { InitialAccessTokenList } from "./initial-access/InitialAccessTokenList";
import { toAddClient } from "./routes/AddClient";
import { toClient } from "./routes/Client";
import { toImportClient } from "./routes/ImportClient";
import { isRealmClient, getProtocolName } from "./utils";
import helpUrls from "../help-urls";
import { useAccess } from "../context/access/Access";
import {
  routableTab,
  RoutableTabs,
} from "../components/routable-tabs/RoutableTabs";
import { ClientsTab, toClients } from "./routes/Clients";

export default function ClientsSection() {
  const { t } = useTranslation("clients");
  const { addAlert, addError } = useAlerts();

  const { adminClient } = useAdminClient();
  const { realm } = useRealm();
  const history = useHistory();

  const [key, setKey] = useState(0);
  const refresh = () => setKey(new Date().getTime());
  const [selectedClient, setSelectedClient] = useState<ClientRepresentation>();

  const { hasAccess } = useAccess();
  const isManager = hasAccess("manage-clients");

  const loader = async (first?: number, max?: number, search?: string) => {
    const params: ClientQuery = {
      first: first!,
      max: max!,
    };
    if (search) {
      params.clientId = search;
      params.search = true;
    }
    return await adminClient.clients.find({ ...params });
  };

  const [toggleDeleteDialog, DeleteConfirm] = useConfirmDialog({
    titleKey: t("clientDelete", { clientId: selectedClient?.clientId }),
    messageKey: "clients:clientDeleteConfirm",
    continueButtonLabel: "common:delete",
    continueButtonVariant: ButtonVariant.danger,
    onConfirm: async () => {
      try {
        await adminClient.clients.del({
          id: selectedClient!.id!,
        });
        addAlert(t("clientDeletedSuccess"), AlertVariant.success);
        refresh();
      } catch (error) {
        addError("clients:clientDeleteError", error);
      }
    },
  });

  const ClientDetailLink = (client: ClientRepresentation) => (
    <Link
      key={client.id}
      to={toClient({ realm, clientId: client.id!, tab: "settings" })}
    >
      {client.clientId}
      {!client.enabled && (
        <Badge key={`${client.id}-disabled`} isRead className="pf-u-ml-sm">
          {t("common:disabled")}
        </Badge>
      )}
    </Link>
  );

  const ClientDescription = (client: ClientRepresentation) => (
    <TableText wrapModifier="truncate">
      {emptyFormatter()(client.description)}
    </TableText>
  );

  const ToolbarItems = () => {
    if (!isManager) return <span />;

    return (
      <>
        <ToolbarItem>
          <Button
            component={(props) => (
              <Link {...props} to={toAddClient({ realm })} />
            )}
          >
            {t("createClient")}
          </Button>
        </ToolbarItem>
        <ToolbarItem>
          <Button
            component={(props) => (
              <Link {...props} to={toImportClient({ realm })} />
            )}
            variant="link"
            data-testid="importClient"
          >
            {t("importClient")}
          </Button>
        </ToolbarItem>
      </>
    );
  };

  const route = (tab: ClientsTab) =>
    routableTab({
      to: toClients({ realm, tab }),
      history,
    });

  return (
    <>
      <ViewHeader
        titleKey="clients:clientList"
        subKey="clients:clientsExplain"
        helpUrl={helpUrls.clientsUrl}
        divider={false}
      />
      <PageSection variant="light" className="pf-u-p-0">
        <RoutableTabs
          mountOnEnter
          isBox
          defaultLocation={toClients({
            realm,
            tab: "list",
          })}
        >
          <Tab
            data-testid="list"
            title={<TabTitleText>{t("clientsList")}</TabTitleText>}
            {...route("list")}
          >
            <DeleteConfirm />
            <KeycloakDataTable
              key={key}
              loader={loader}
              isPaginated
              ariaLabelKey="clients:clientList"
              searchPlaceholderKey="clients:searchForClient"
              toolbarItem={<ToolbarItems />}
              actionResolver={(rowData: IRowData) => {
                const client: ClientRepresentation = rowData.data;
                const actions: Action<ClientRepresentation>[] = [
                  {
                    title: t("common:export"),
                    onClick() {
                      exportClient(client);
                    },
                  },
                ];

                if (
                  !isRealmClient(client) &&
                  (isManager || client.access?.configure)
                ) {
                  actions.push({
                    title: t("common:delete"),
                    onClick() {
                      setSelectedClient(client);
                      toggleDeleteDialog();
                    },
                  });
                }

                return actions;
              }}
              columns={[
                {
                  name: "clientId",
                  displayKey: "common:clientId",
                  cellRenderer: ClientDetailLink,
                },
                {
                  name: "protocol",
                  displayKey: "common:type",
                  cellRenderer: (client) =>
                    getProtocolName(t, client.protocol ?? "openid-connect"),
                },
                {
                  name: "description",
                  displayKey: "common:description",
                  transforms: [cellWidth(20)],
                  cellRenderer: ClientDescription,
                },
                {
                  name: "baseUrl",
                  displayKey: "clients:homeURL",
                  cellFormatters: [formattedLinkTableCell(), emptyFormatter()],
                  cellRenderer: (c) =>
                    convertClientToUrl(c, adminClient.baseUrl),
                },
              ]}
            />
          </Tab>
          <Tab
            data-testid="initialAccessToken"
            title={<TabTitleText>{t("initialAccessToken")}</TabTitleText>}
            {...route("initial-access-token")}
          >
            <InitialAccessTokenList />
          </Tab>
        </RoutableTabs>
      </PageSection>
    </>
  );
}
