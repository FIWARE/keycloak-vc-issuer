import {
  Alert,
  AlertVariant,
  Button,
  ButtonVariant,
  Form,
  FormGroup,
  Modal,
  ModalVariant,
  Switch,
  Text,
  TextContent,
} from "@patternfly/react-core";
import FileSaver from "file-saver";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useAlerts } from "../components/alert/Alerts";
import { useAdminClient } from "../context/auth/AdminClient";
import { useRealm } from "../context/realm-context/RealmContext";
import { prettyPrintJSON } from "../util";

import "./partial-export.css";

export type PartialExportDialogProps = {
  isOpen: boolean;
  onClose: () => void;
};

export const PartialExportDialog = ({
  isOpen,
  onClose,
}: PartialExportDialogProps) => {
  const { t } = useTranslation("realm-settings");
  const { realm } = useRealm();
  const { adminClient } = useAdminClient();
  const { addAlert, addError } = useAlerts();

  const [exportGroupsAndRoles, setExportGroupsAndRoles] = useState(false);
  const [exportClients, setExportClients] = useState(false);
  const [isExporting, setIsExporting] = useState(false);

  const showWarning = exportGroupsAndRoles || exportClients;

  async function exportRealm() {
    setIsExporting(true);

    try {
      const realmExport = await adminClient.realms.export({
        realm,
        exportClients,
        exportGroupsAndRoles,
      });

      FileSaver.saveAs(
        new Blob([prettyPrintJSON(realmExport)], {
          type: "application/json",
        }),
        "realm-export.json"
      );

      addAlert(t("exportSuccess"), AlertVariant.success);
      onClose();
    } catch (error) {
      addError("exportFail", error);
    }

    setIsExporting(false);
  }

  return (
    <Modal
      variant={ModalVariant.small}
      title={t("partialExport")}
      isOpen={isOpen}
      onClose={onClose}
      actions={[
        <Button
          key="export"
          data-testid="export-button"
          isDisabled={isExporting}
          onClick={exportRealm}
        >
          {t("common:export")}
        </Button>,
        <Button
          key="cancel"
          data-testid="cancel-button"
          variant={ButtonVariant.link}
          onClick={onClose}
        >
          {t("common:cancel")}
        </Button>,
      ]}
    >
      <TextContent>
        <Text>{t("partialExportHeaderText")}</Text>
      </TextContent>
      <Form
        isHorizontal
        className="keycloak__realm-settings__partial-import_form"
      >
        <FormGroup
          label={t("includeGroupsAndRoles")}
          fieldId="include-groups-and-roles-check"
          hasNoPaddingTop
        >
          <Switch
            id="include-groups-and-roles-check"
            data-testid="include-groups-and-roles-check"
            isChecked={exportGroupsAndRoles}
            onChange={setExportGroupsAndRoles}
            label={t("common:on")}
            labelOff={t("common:off")}
            aria-label={t("includeGroupsAndRoles")}
          />
        </FormGroup>
        <FormGroup
          label={t("includeClients")}
          fieldId="include-clients-check"
          hasNoPaddingTop
        >
          <Switch
            id="include-clients-check"
            data-testid="include-clients-check"
            onChange={setExportClients}
            isChecked={exportClients}
            label={t("common:on")}
            labelOff={t("common:off")}
            aria-label={t("includeClients")}
          />
        </FormGroup>
      </Form>

      {showWarning && (
        <Alert
          data-testid="warning-message"
          variant="warning"
          title={t("exportWarningTitle")}
          isInline
        >
          {t("exportWarningDescription")}
        </Alert>
      )}
    </Modal>
  );
};
