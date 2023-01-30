import { PageSection } from "@patternfly/react-core";

import { useTranslation } from "react-i18next";
import { useParams } from "react-router-dom";

import { useAdminClient } from "../context/auth/AdminClient";
import { useRealm } from "../context/realm-context/RealmContext";
import SessionsTable from "../sessions/SessionsTable";
import type { UserParams } from "./routes/User";

export const UserSessions = () => {
  const { adminClient } = useAdminClient();
  const { id } = useParams<UserParams>();
  const { realm } = useRealm();
  const { t } = useTranslation("sessions");

  const loader = () => adminClient.users.listSessions({ id, realm });

  return (
    <PageSection variant="light" className="pf-u-p-0">
      <SessionsTable
        loader={loader}
        hiddenColumns={["username"]}
        emptyInstructions={t("noSessionsForUser")}
        logoutUser={id}
      />
    </PageSection>
  );
};
