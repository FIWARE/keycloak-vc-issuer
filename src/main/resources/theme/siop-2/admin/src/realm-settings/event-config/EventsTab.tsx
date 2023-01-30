import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useForm } from "react-hook-form";
import {
  AlertVariant,
  ButtonVariant,
  PageSection,
  Tab,
  Tabs,
  TabTitleText,
  Title,
} from "@patternfly/react-core";

import type RealmRepresentation from "@keycloak/keycloak-admin-client/lib/defs/realmRepresentation";
import type { RealmEventsConfigRepresentation } from "@keycloak/keycloak-admin-client/lib/defs/realmEventsConfigRepresentation";
import { FormAccess } from "../../components/form-access/FormAccess";
import { useRealm } from "../../context/realm-context/RealmContext";
import { useAlerts } from "../../components/alert/Alerts";
import { useFetch, useAdminClient } from "../../context/auth/AdminClient";
import { EventConfigForm, EventsType } from "./EventConfigForm";
import { useConfirmDialog } from "../../components/confirm-dialog/ConfirmDialog";
import { EventsTypeTable, EventType } from "./EventsTypeTable";
import { AddEventTypesDialog } from "./AddEventTypesDialog";
import { EventListenersForm } from "./EventListenersForm";
import { convertToFormValues } from "../../util";

type EventsTabProps = {
  realm: RealmRepresentation;
};

type EventsConfigForm = RealmEventsConfigRepresentation & {
  adminEventsExpiration?: number;
};

export const EventsTab = ({ realm }: EventsTabProps) => {
  const { t } = useTranslation("realm-settings");
  const form = useForm<EventsConfigForm>();
  const { setValue, handleSubmit, watch } = form;

  const [key, setKey] = useState(0);
  const refresh = () => setKey(new Date().getTime());
  const [tableKey, setTableKey] = useState(0);
  const reload = () => setTableKey(new Date().getTime());

  const [activeTab, setActiveTab] = useState("event");
  const [events, setEvents] = useState<RealmEventsConfigRepresentation>();
  const [type, setType] = useState<EventsType>();
  const [addEventType, setAddEventType] = useState(false);

  const { adminClient } = useAdminClient();
  const { addAlert, addError } = useAlerts();
  const { realm: realmName } = useRealm();

  const setupForm = (eventConfig?: EventsConfigForm) => {
    setEvents(eventConfig);
    convertToFormValues(eventConfig, setValue);
  };

  const clear = async (type: EventsType) => {
    setType(type);
    toggleDeleteDialog();
  };

  const [toggleDeleteDialog, DeleteConfirm] = useConfirmDialog({
    titleKey: "realm-settings:deleteEvents",
    messageKey: "realm-settings:deleteEventsConfirm",
    continueButtonLabel: "common:clear",
    continueButtonVariant: ButtonVariant.danger,
    onConfirm: async () => {
      try {
        switch (type) {
          case "admin":
            await adminClient.realms.clearAdminEvents({ realm: realmName });
            break;
          case "user":
            await adminClient.realms.clearEvents({ realm: realmName });
            break;
        }
        addAlert(t(`${type}-events-cleared`), AlertVariant.success);
      } catch (error) {
        addError(`realm-settings:${type}-events-cleared-error`, error);
      }
    },
  });

  useFetch(
    () => adminClient.realms.getConfigEvents({ realm: realmName }),
    (eventConfig) => {
      setupForm({
        ...eventConfig,
        adminEventsExpiration: realm.attributes?.adminEventsExpiration,
      });
      reload();
    },
    [key]
  );

  const save = async (config: EventsConfigForm) => {
    const updatedEventListener =
      events?.eventsListeners !== config.eventsListeners;

    const { adminEventsExpiration, ...eventConfig } = config;
    if (realm.attributes?.adminEventsExpiration !== adminEventsExpiration) {
      await adminClient.realms.update(
        { realm: realmName },
        {
          ...realm,
          attributes: { ...(realm.attributes || {}), adminEventsExpiration },
        }
      );
    }

    try {
      await adminClient.realms.updateConfigEvents(
        { realm: realmName },
        eventConfig
      );
      setupForm({ ...events, ...eventConfig, adminEventsExpiration });
      addAlert(
        updatedEventListener
          ? t("realm-settings:saveEventListenersSuccess")
          : t("realm-settings:eventConfigSuccessfully"),
        AlertVariant.success
      );
    } catch (error) {
      addError(
        updatedEventListener
          ? t("realm-settings:saveEventListenersError")
          : t("realm-settings:eventConfigError"),
        error
      );
    }
  };

  const addEventTypes = async (eventTypes: EventType[]) => {
    const eventsTypes = eventTypes.map((type) => type.id);
    const enabledEvents = events!.enabledEventTypes?.concat(eventsTypes);
    await addEvents(enabledEvents);
  };

  const addEvents = async (events: string[] = []) => {
    const eventConfig = { ...form.getValues(), enabledEventTypes: events };
    await save(eventConfig);
    setAddEventType(false);
    refresh();
  };

  const eventsEnabled: boolean = watch("eventsEnabled") || false;
  return (
    <>
      <DeleteConfirm />
      {addEventType && (
        <AddEventTypesDialog
          onConfirm={(eventTypes) => addEventTypes(eventTypes)}
          configured={events?.enabledEventTypes || []}
          onClose={() => setAddEventType(false)}
        />
      )}
      <Tabs
        activeKey={activeTab}
        onSelect={(_, key) => setActiveTab(key as string)}
      >
        <Tab
          eventKey="event"
          title={<TabTitleText>{t("eventListeners")}</TabTitleText>}
          data-testid="rs-event-listeners-tab"
        >
          <PageSection>
            <FormAccess
              role="manage-events"
              isHorizontal
              onSubmit={handleSubmit(save)}
            >
              <EventListenersForm form={form} reset={() => setupForm(events)} />
            </FormAccess>
          </PageSection>
        </Tab>
        <Tab
          eventKey="user"
          title={<TabTitleText>{t("userEventsSettings")}</TabTitleText>}
          data-testid="rs-events-tab"
        >
          <PageSection>
            <Title headingLevel="h1" size="xl">
              {t("userEventsConfig")}
            </Title>
          </PageSection>
          <PageSection>
            <FormAccess
              role="manage-events"
              isHorizontal
              onSubmit={handleSubmit(save)}
            >
              <EventConfigForm
                type="user"
                form={form}
                reset={() => setupForm(events)}
                clear={() => clear("user")}
              />
            </FormAccess>
          </PageSection>
          {eventsEnabled && (
            <PageSection>
              <EventsTypeTable
                key={tableKey}
                addTypes={() => setAddEventType(true)}
                loader={() =>
                  Promise.resolve(
                    events?.enabledEventTypes?.map((id) => {
                      return { id };
                    }) || []
                  )
                }
                onDelete={(value) => {
                  const enabledEventTypes = events?.enabledEventTypes?.filter(
                    (e) => e !== value.id
                  );
                  addEvents(enabledEventTypes);
                  setEvents({ ...events, enabledEventTypes });
                }}
              />
            </PageSection>
          )}
        </Tab>
        <Tab
          eventKey="admin"
          title={<TabTitleText>{t("adminEventsSettings")}</TabTitleText>}
          data-testid="rs-admin-events-tab"
        >
          <PageSection>
            <Title headingLevel="h4" size="xl">
              {t("adminEventsConfig")}
            </Title>
          </PageSection>
          <PageSection>
            <FormAccess
              role="manage-events"
              isHorizontal
              onSubmit={handleSubmit(save)}
            >
              <EventConfigForm
                type="admin"
                form={form}
                reset={() => setupForm(events)}
                clear={() => clear("admin")}
              />
            </FormAccess>
          </PageSection>
        </Tab>
      </Tabs>
    </>
  );
};
