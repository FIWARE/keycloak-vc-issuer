import "@patternfly/patternfly/patternfly-addons.css";
import "@patternfly/react-core/dist/styles/base.css";

import { StrictMode } from "react";
import ReactDOM from "react-dom";

import { App } from "./App";
import { initAdminClient } from "./context/auth/AdminClient";
import { initI18n } from "./i18n";

import "./index.css";

async function initialize() {
  const { keycloak, adminClient } = await initAdminClient();

  await initI18n(adminClient);

  ReactDOM.render(
    <StrictMode>
      <App keycloak={keycloak} adminClient={adminClient} />
    </StrictMode>,
    document.getElementById("app")
  );
}

initialize();
