import { useState } from "react";
import { useHistory, useParams } from "react-router-dom";
import { useNavigate } from "react-router-dom-v5-compat";
import { useTranslation } from "react-i18next";
import {
  AlertVariant,
  PageSection,
  Tab,
  TabTitleText,
} from "@patternfly/react-core";

import type ClientRepresentation from "@keycloak/keycloak-admin-client/lib/defs/clientRepresentation";
import type { ProtocolMapperTypeRepresentation } from "@keycloak/keycloak-admin-client/lib/defs/serverInfoRepesentation";
import type ProtocolMapperRepresentation from "@keycloak/keycloak-admin-client/lib/defs/protocolMapperRepresentation";
import { KeycloakSpinner } from "../../components/keycloak-spinner/KeycloakSpinner";
import { MapperList } from "../../client-scopes/details/MapperList";
import { ViewHeader } from "../../components/view-header/ViewHeader";
import { useAdminClient, useFetch } from "../../context/auth/AdminClient";
import {
  routableTab,
  RoutableTabs,
} from "../../components/routable-tabs/RoutableTabs";
import {
  DedicatedScopeDetailsParams,
  DedicatedScopeTab,
  toDedicatedScope,
} from "../routes/DedicatedScopeDetails";
import { toMapper } from "../routes/Mapper";
import { useAlerts } from "../../components/alert/Alerts";
import { DedicatedScope } from "./DecicatedScope";

export default function DedicatedScopes() {
  const { t } = useTranslation("clients");
  const history = useHistory();
  const navigate = useNavigate();
  const { realm, clientId } = useParams<DedicatedScopeDetailsParams>();

  const { adminClient } = useAdminClient();
  const { addAlert, addError } = useAlerts();

  const [client, setClient] = useState<ClientRepresentation>();

  useFetch(() => adminClient.clients.findOne({ id: clientId }), setClient, []);

  const route = (tab: DedicatedScopeTab) =>
    routableTab({
      to: toDedicatedScope({ realm, clientId, tab }),
      history,
    });

  if (!client) {
    return <KeycloakSpinner />;
  }

  const addMappers = async (
    mappers: ProtocolMapperTypeRepresentation | ProtocolMapperRepresentation[]
  ): Promise<void> => {
    if (!Array.isArray(mappers)) {
      const mapper = mappers as ProtocolMapperTypeRepresentation;
      navigate(
        toMapper({
          realm,
          id: client.id!,
          mapperId: mapper.id!,
        })
      );
    } else {
      try {
        await adminClient.clients.addMultipleProtocolMappers(
          { id: client.id! },
          mappers as ProtocolMapperRepresentation[]
        );
        setClient(await adminClient.clients.findOne({ id: client.id! }));
        addAlert(t("common:mappingCreatedSuccess"), AlertVariant.success);
      } catch (error) {
        addError("common:mappingCreatedError", error);
      }
    }
  };

  const onDeleteMapper = async (mapper: ProtocolMapperRepresentation) => {
    try {
      await adminClient.clients.delProtocolMapper({
        id: client.id!,
        mapperId: mapper.id!,
      });
      setClient({
        ...client,
        protocolMappers: client.protocolMappers?.filter(
          (m) => m.id !== mapper.id
        ),
      });
      addAlert(t("common:mappingDeletedSuccess"), AlertVariant.success);
    } catch (error) {
      addError("common:mappingDeletedError", error);
    }
    return true;
  };

  return (
    <>
      <ViewHeader
        titleKey={client.clientId!}
        subKey="clients-help:dedicatedScopeExplain"
        divider={false}
      />
      <PageSection variant="light" className="pf-u-p-0">
        <RoutableTabs
          isBox
          mountOnEnter
          defaultLocation={toDedicatedScope({
            realm,
            clientId,
            tab: "mappers",
          })}
        >
          <Tab
            title={<TabTitleText>{t("mappers")}</TabTitleText>}
            data-testid="mappersTab"
            {...route("mappers")}
          >
            <MapperList
              model={client}
              onAdd={addMappers}
              onDelete={onDeleteMapper}
              detailLink={(mapperId) =>
                toMapper({ realm, id: client.id!, mapperId })
              }
            />
          </Tab>
          <Tab
            title={<TabTitleText>{t("scope")}</TabTitleText>}
            data-testid="scopeTab"
            {...route("scope")}
          >
            <DedicatedScope client={client} />
          </Tab>
        </RoutableTabs>
      </PageSection>
    </>
  );
}
