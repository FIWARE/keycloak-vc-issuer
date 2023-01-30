import {
  ActionGroup,
  Button,
  Chip,
  ChipGroup,
  DatePicker,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Dropdown,
  DropdownToggle,
  Flex,
  FlexItem,
  Form,
  FormGroup,
  PageSection,
  Select,
  SelectOption,
  SelectVariant,
  Tab,
  TabTitleText,
  Tooltip,
} from "@patternfly/react-core";
import { CheckCircleIcon, WarningTriangleIcon } from "@patternfly/react-icons";
import { cellWidth, expandable } from "@patternfly/react-table";
import type EventRepresentation from "@keycloak/keycloak-admin-client/lib/defs/eventRepresentation";
import type EventType from "@keycloak/keycloak-admin-client/lib/defs/eventTypes";
import type { RealmEventsConfigRepresentation } from "@keycloak/keycloak-admin-client/lib/defs/realmEventsConfigRepresentation";
import { pickBy } from "lodash-es";
import { useState } from "react";
import { Controller, useForm } from "react-hook-form";
import { Trans, useTranslation } from "react-i18next";
import { useHistory } from "react-router-dom";
import { Link } from "react-router-dom-v5-compat";
import { ListEmptyState } from "../components/list-empty-state/ListEmptyState";
import { KeycloakDataTable } from "../components/table-toolbar/KeycloakDataTable";
import { ViewHeader } from "../components/view-header/ViewHeader";
import { KeycloakTextInput } from "../components/keycloak-text-input/KeycloakTextInput";
import { useAdminClient, useFetch } from "../context/auth/AdminClient";
import { useRealm } from "../context/realm-context/RealmContext";
import { toRealmSettings } from "../realm-settings/routes/RealmSettings";
import { toUser } from "../user/routes/User";
import useFormatDate, { FORMAT_DATE_AND_TIME } from "../utils/useFormatDate";
import { AdminEvents } from "./AdminEvents";
import helpUrls from "../help-urls";
import {
  routableTab,
  RoutableTabs,
} from "../components/routable-tabs/RoutableTabs";
import { EventsTab, toEvents } from "./routes/Events";

import "./events.css";

type UserEventSearchForm = {
  client: string;
  dateFrom: string;
  dateTo: string;
  user: string;
  type: EventType[];
};

const defaultValues: UserEventSearchForm = {
  client: "",
  dateFrom: "",
  dateTo: "",
  user: "",
  type: [],
};

const StatusRow = (event: EventRepresentation) =>
  !event.error ? (
    <span>
      <CheckCircleIcon color="green" /> {event.type}
    </span>
  ) : (
    <Tooltip content={event.error}>
      <span>
        <WarningTriangleIcon color="orange" /> {event.type}
      </span>
    </Tooltip>
  );

const DetailCell = (event: EventRepresentation) => (
  <DescriptionList isHorizontal className="keycloak_eventsection_details">
    {event.details &&
      Object.entries(event.details).map(([key, value]) => (
        <DescriptionListGroup key={key}>
          <DescriptionListTerm>{key}</DescriptionListTerm>
          <DescriptionListDescription>{value}</DescriptionListDescription>
        </DescriptionListGroup>
      ))}
  </DescriptionList>
);

export default function EventsSection() {
  const { t } = useTranslation("events");
  const { adminClient } = useAdminClient();
  const { realm } = useRealm();
  const formatDate = useFormatDate();
  const [key, setKey] = useState(0);
  const [searchDropdownOpen, setSearchDropdownOpen] = useState(false);
  const [selectOpen, setSelectOpen] = useState(false);
  const [events, setEvents] = useState<RealmEventsConfigRepresentation>();
  const [activeFilters, setActiveFilters] = useState<
    Partial<UserEventSearchForm>
  >({});

  const filterLabels: Record<keyof UserEventSearchForm, string> = {
    client: t("client"),
    dateFrom: t("dateFrom"),
    dateTo: t("dateTo"),
    user: t("userId"),
    type: t("eventType"),
  };

  const {
    getValues,
    register,
    reset,
    formState: { isDirty },
    control,
  } = useForm<UserEventSearchForm>({
    shouldUnregister: false,
    mode: "onChange",
    defaultValues,
  });

  useFetch(
    () => adminClient.realms.getConfigEvents({ realm }),
    (events) => setEvents(events),
    []
  );

  function loader(first?: number, max?: number) {
    return adminClient.realms.findEvents({
      // The admin client wants 'dateFrom' and 'dateTo' to be Date objects, however it cannot actually handle them so we need to cast to any.
      ...(activeFilters as any),
      realm,
      first,
      max,
    });
  }

  function submitSearch() {
    setSearchDropdownOpen(false);
    commitFilters();
  }

  function resetSearch() {
    reset();
    commitFilters();
  }

  function removeFilter(key: keyof UserEventSearchForm) {
    const formValues: UserEventSearchForm = { ...getValues() };
    delete formValues[key];

    reset({ ...defaultValues, ...formValues });
    commitFilters();
  }

  function removeFilterValue(
    key: keyof UserEventSearchForm,
    valueToRemove: EventType
  ) {
    const formValues = getValues();
    const fieldValue = formValues[key];
    const newFieldValue = Array.isArray(fieldValue)
      ? fieldValue.filter((val) => val !== valueToRemove)
      : fieldValue;

    reset({ ...formValues, [key]: newFieldValue });
    commitFilters();
  }

  function commitFilters() {
    const newFilters: Partial<UserEventSearchForm> = pickBy(
      getValues(),
      (value) => value !== "" || (Array.isArray(value) && value.length > 0)
    );

    setActiveFilters(newFilters);
    setKey(key + 1);
  }

  function refresh() {
    commitFilters();
  }

  const UserDetailLink = (event: EventRepresentation) => (
    <>
      {event.userId && (
        <Link
          key={`link-${event.time}-${event.type}`}
          to={toUser({
            realm,
            id: event.userId,
            tab: "settings",
          })}
        >
          {event.userId}
        </Link>
      )}
      {!event.userId && t("noUserDetails")}
    </>
  );

  const userEventSearchFormDisplay = () => {
    return (
      <Flex
        direction={{ default: "column" }}
        spaceItems={{ default: "spaceItemsNone" }}
      >
        <FlexItem>
          <Dropdown
            id="user-events-search-select"
            data-testid="UserEventsSearchSelector"
            className="pf-u-ml-md"
            toggle={
              <DropdownToggle
                data-testid="userEventsSearchSelectorToggle"
                onToggle={(isOpen) => setSearchDropdownOpen(isOpen)}
                className="keycloak__events_search_selector_dropdown__toggle"
              >
                {t("searchForUserEvent")}
              </DropdownToggle>
            }
            isOpen={searchDropdownOpen}
          >
            <Form
              isHorizontal
              className="keycloak__events_search__form"
              data-testid="searchForm"
            >
              <FormGroup
                label={t("userId")}
                fieldId="kc-userId"
                className="keycloak__events_search__form_label"
              >
                <KeycloakTextInput
                  ref={register()}
                  type="text"
                  id="kc-userId"
                  name="user"
                  data-testid="userId-searchField"
                />
              </FormGroup>
              <FormGroup
                label={t("eventType")}
                fieldId="kc-eventType"
                className="keycloak__events_search__form_label"
              >
                <Controller
                  name="type"
                  control={control}
                  render={({
                    onChange,
                    value,
                  }: {
                    onChange: (newValue: EventType[]) => void;
                    value: EventType[];
                  }) => (
                    <Select
                      className="keycloak__events_search__type_select"
                      name="eventType"
                      data-testid="event-type-searchField"
                      chipGroupProps={{
                        numChips: 1,
                        expandedText: t("common:hide"),
                        collapsedText: t("common:showRemaining"),
                      }}
                      variant={SelectVariant.typeaheadMulti}
                      typeAheadAriaLabel="Select"
                      onToggle={(isOpen) => setSelectOpen(isOpen)}
                      selections={value}
                      onSelect={(_, selectedValue) => {
                        const option = selectedValue.toString() as EventType;
                        const changedValue = value.includes(option)
                          ? value.filter((item) => item !== option)
                          : [...value, option];

                        onChange(changedValue);
                      }}
                      onClear={(event) => {
                        event.stopPropagation();
                        onChange([]);
                      }}
                      isOpen={selectOpen}
                      aria-labelledby={"eventType"}
                      chipGroupComponent={
                        <ChipGroup>
                          {value.map((chip) => (
                            <Chip
                              key={chip}
                              onClick={(event) => {
                                event.stopPropagation();
                                onChange(value.filter((val) => val !== chip));
                              }}
                            >
                              {chip}
                            </Chip>
                          ))}
                        </ChipGroup>
                      }
                    >
                      {events?.enabledEventTypes?.map((option) => (
                        <SelectOption key={option} value={option} />
                      ))}
                    </Select>
                  )}
                />
              </FormGroup>
              <FormGroup
                label={t("client")}
                fieldId="kc-client"
                className="keycloak__events_search__form_label"
              >
                <KeycloakTextInput
                  ref={register()}
                  type="text"
                  id="kc-client"
                  name="client"
                  data-testid="client-searchField"
                />
              </FormGroup>
              <FormGroup
                label={t("dateFrom")}
                fieldId="kc-dateFrom"
                className="keycloak__events_search__form_label"
              >
                <Controller
                  name="dateFrom"
                  control={control}
                  render={({ onChange, value }) => (
                    <DatePicker
                      className="pf-u-w-100"
                      value={value}
                      onChange={(value) => onChange(value)}
                      inputProps={{ id: "kc-dateFrom" }}
                    />
                  )}
                />
              </FormGroup>
              <FormGroup
                label={t("dateTo")}
                fieldId="kc-dateTo"
                className="keycloak__events_search__form_label"
              >
                <Controller
                  name="dateTo"
                  control={control}
                  render={({ onChange, value }) => (
                    <DatePicker
                      className="pf-u-w-100"
                      value={value}
                      onChange={(value) => onChange(value)}
                      inputProps={{ id: "kc-dateTo" }}
                    />
                  )}
                />
              </FormGroup>
              <ActionGroup>
                <Button
                  variant={"primary"}
                  onClick={submitSearch}
                  data-testid="search-events-btn"
                  isDisabled={!isDirty}
                >
                  {t("searchUserEventsBtn")}
                </Button>
                <Button
                  variant="secondary"
                  onClick={resetSearch}
                  isDisabled={!isDirty}
                >
                  {t("resetBtn")}
                </Button>
              </ActionGroup>
            </Form>
          </Dropdown>
          <Button
            className="pf-u-ml-md"
            onClick={refresh}
            data-testid="refresh-btn"
          >
            {t("refresh")}
          </Button>
        </FlexItem>
        <FlexItem>
          {Object.entries(activeFilters).length > 0 && (
            <div className="keycloak__searchChips pf-u-ml-md">
              {Object.entries(activeFilters).map((filter) => {
                const [key, value] = filter as [
                  keyof UserEventSearchForm,
                  string | EventType[]
                ];

                return (
                  <ChipGroup
                    className="pf-u-mt-md pf-u-mr-md"
                    key={key}
                    categoryName={filterLabels[key]}
                    isClosable
                    onClick={() => removeFilter(key)}
                  >
                    {typeof value === "string" ? (
                      <Chip isReadOnly>{value}</Chip>
                    ) : (
                      value.map((entry) => (
                        <Chip
                          key={entry}
                          onClick={() => removeFilterValue(key, entry)}
                        >
                          {entry}
                        </Chip>
                      ))
                    )}
                  </ChipGroup>
                );
              })}
            </div>
          )}
        </FlexItem>
      </Flex>
    );
  };

  const history = useHistory();
  const route = (tab: EventsTab) =>
    routableTab({
      to: toEvents({ realm, tab }),
      history,
    });

  return (
    <>
      <ViewHeader
        titleKey="events:title"
        subKey={
          <Trans i18nKey="events:eventExplain">
            If you want to configure user events, Admin events or Event
            listeners, please enter
            <Link to={toRealmSettings({ realm, tab: "events" })}>
              {t("eventConfig")}
            </Link>
            page realm settings to configure.
          </Trans>
        }
        helpUrl={helpUrls.eventsUrl}
        divider={false}
      />
      <PageSection variant="light" className="pf-u-p-0">
        <RoutableTabs
          isBox
          defaultLocation={toEvents({ realm, tab: "user-events" })}
        >
          <Tab
            title={<TabTitleText>{t("userEvents")}</TabTitleText>}
            {...route("user-events")}
          >
            <div className="keycloak__events_table">
              <KeycloakDataTable
                key={key}
                loader={loader}
                detailColumns={[
                  {
                    name: "details",
                    enabled: (event) => event.details !== undefined,
                    cellRenderer: DetailCell,
                  },
                ]}
                isPaginated
                ariaLabelKey="events:title"
                toolbarItem={userEventSearchFormDisplay()}
                columns={[
                  {
                    name: "time",
                    displayKey: "events:time",
                    cellFormatters: [expandable],
                    cellRenderer: (row) =>
                      formatDate(new Date(row.time!), FORMAT_DATE_AND_TIME),
                  },
                  {
                    name: "userId",
                    displayKey: "events:user",
                    cellRenderer: UserDetailLink,
                  },
                  {
                    name: "type",
                    displayKey: "events:eventType",
                    cellRenderer: StatusRow,
                  },
                  {
                    name: "ipAddress",
                    displayKey: "events:ipAddress",
                    transforms: [cellWidth(10)],
                  },
                  {
                    name: "clientId",
                    displayKey: "events:client",
                  },
                ]}
                emptyState={
                  <ListEmptyState
                    message={t("emptyEvents")}
                    instructions={t("emptyEventsInstructions")}
                  />
                }
                isSearching={Object.keys(activeFilters).length > 0}
              />
            </div>
          </Tab>
          <Tab
            title={<TabTitleText>{t("adminEvents")}</TabTitleText>}
            data-testid="admin-events-tab"
            {...route("admin-events")}
          >
            <AdminEvents />
          </Tab>
        </RoutableTabs>
      </PageSection>
    </>
  );
}
