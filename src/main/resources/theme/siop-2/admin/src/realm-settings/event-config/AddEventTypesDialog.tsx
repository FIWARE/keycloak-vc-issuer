import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button, Modal, ModalVariant } from "@patternfly/react-core";

import { EventsTypeTable, EventType } from "./EventsTypeTable";
import { useServerInfo } from "../../context/server-info/ServerInfoProvider";

type AddEventTypesDialogProps = {
  onConfirm: (selected: EventType[]) => void;
  onClose: () => void;
  configured: string[];
};

export const AddEventTypesDialog = ({
  onConfirm,
  onClose,
  configured,
}: AddEventTypesDialogProps) => {
  const { t } = useTranslation("realm-settings");
  const { enums } = useServerInfo();

  const [selectedTypes, setSelectedTypes] = useState<EventType[]>([]);
  return (
    <Modal
      variant={ModalVariant.medium}
      title={t("addTypes")}
      isOpen={true}
      onClose={onClose}
      actions={[
        <Button
          data-testid="addEventTypeConfirm"
          key="confirm"
          variant="primary"
          onClick={() => onConfirm(selectedTypes)}
        >
          {t("common:add")}
        </Button>,
        <Button
          data-testid="moveCancel"
          key="cancel"
          variant="link"
          onClick={onClose}
        >
          {t("common:cancel")}
        </Button>,
      ]}
    >
      <EventsTypeTable
        onSelect={(selected) => setSelectedTypes(selected)}
        loader={() =>
          Promise.resolve(
            enums!["eventType"]
              .filter((type) => !configured.includes(type))
              .map((id) => {
                return { id };
              })
          )
        }
      />
    </Modal>
  );
};
