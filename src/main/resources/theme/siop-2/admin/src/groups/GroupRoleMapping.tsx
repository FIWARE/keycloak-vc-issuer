import { useTranslation } from "react-i18next";
import { AlertVariant } from "@patternfly/react-core";

import type { RoleMappingPayload } from "@keycloak/keycloak-admin-client/lib/defs/roleRepresentation";
import { useAdminClient } from "../context/auth/AdminClient";
import { useAlerts } from "../components/alert/Alerts";
import { RoleMapping, Row } from "../components/role-mapping/RoleMapping";

type GroupRoleMappingProps = {
  id: string;
  name: string;
};

export const GroupRoleMapping = ({ id, name }: GroupRoleMappingProps) => {
  const { t } = useTranslation("clients");
  const { adminClient } = useAdminClient();
  const { addAlert, addError } = useAlerts();

  const assignRoles = async (rows: Row[]) => {
    try {
      const realmRoles = rows
        .filter((row) => row.client === undefined)
        .map((row) => row.role as RoleMappingPayload)
        .flat();
      await adminClient.groups.addRealmRoleMappings({
        id,
        roles: realmRoles,
      });
      await Promise.all(
        rows
          .filter((row) => row.client !== undefined)
          .map((row) =>
            adminClient.groups.addClientRoleMappings({
              id,
              clientUniqueId: row.client!.id!,
              roles: [row.role as RoleMappingPayload],
            })
          )
      );
      addAlert(t("roleMappingUpdatedSuccess"), AlertVariant.success);
    } catch (error) {
      addError("clients:roleMappingUpdatedError", error);
    }
  };

  return <RoleMapping name={name} id={id} type="groups" save={assignRoles} />;
};
