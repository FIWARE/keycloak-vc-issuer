import {
  FormGroup,
  NumberInput,
  Select,
  SelectOption,
  SelectVariant,
} from "@patternfly/react-core";
import { useTranslation } from "react-i18next";

import { HelpItem } from "../../components/help-enabler/HelpItem";
import { UseFormMethods, useWatch, Controller } from "react-hook-form";
import { FormAccess } from "../../components/form-access/FormAccess";
import { isEqual } from "lodash-es";
import { WizardSectionHeader } from "../../components/wizard-section-header/WizardSectionHeader";
import useToggle from "../../utils/useToggle";

export type SettingsCacheProps = {
  form: UseFormMethods;
  showSectionHeading?: boolean;
  showSectionDescription?: boolean;
  unWrap?: boolean;
};

const CacheFields = ({ form }: { form: UseFormMethods }) => {
  const { t } = useTranslation("user-federation");

  const [isCachePolicyOpen, toggleCachePolicy] = useToggle();
  const [isEvictionHourOpen, toggleEvictionHour] = useToggle();
  const [isEvictionMinuteOpen, toggleEvictionMinute] = useToggle();

  const [isEvictionDayOpen, toggleEvictionDay] = useToggle();

  const cachePolicyType = useWatch({
    control: form.control,
    name: "config.cachePolicy",
  });

  const hourOptions = [
    <SelectOption key={0} value={[`${0}`]} isPlaceholder>
      {[`0${0}`]}
    </SelectOption>,
  ];
  let hourDisplay = "";
  for (let index = 1; index < 24; index++) {
    if (index < 10) {
      hourDisplay = `0${index}`;
    } else {
      hourDisplay = `${index}`;
    }
    hourOptions.push(
      <SelectOption key={index} value={[`${index}`]}>
        {hourDisplay}
      </SelectOption>
    );
  }

  const minuteOptions = [
    <SelectOption key={0} value={[`${0}`]} isPlaceholder>
      {[`0${0}`]}
    </SelectOption>,
  ];
  let minuteDisplay = "";
  for (let index = 1; index < 60; index++) {
    if (index < 10) {
      minuteDisplay = `0${index}`;
    } else {
      minuteDisplay = `${index}`;
    }
    minuteOptions.push(
      <SelectOption key={index} value={[`${index}`]}>
        {minuteDisplay}
      </SelectOption>
    );
  }

  return (
    <>
      <FormGroup
        label={t("cachePolicy")}
        labelIcon={
          <HelpItem
            helpText="user-federation-help:cachePolicyHelp"
            fieldLabelId="user-federation:cachePolicy"
          />
        }
        fieldId="kc-cache-policy"
      >
        <Controller
          name="config.cachePolicy"
          defaultValue={["DEFAULT"]}
          control={form.control}
          render={({ onChange, value }) => (
            <Select
              toggleId="kc-cache-policy"
              required
              onToggle={toggleCachePolicy}
              isOpen={isCachePolicyOpen}
              onSelect={(_, value) => {
                onChange(value as string);
                toggleCachePolicy();
              }}
              selections={value}
              variant={SelectVariant.single}
              data-testid="kerberos-cache-policy"
            >
              <SelectOption key={0} value={["DEFAULT"]} isPlaceholder />
              <SelectOption key={1} value={["EVICT_DAILY"]} />
              <SelectOption key={2} value={["EVICT_WEEKLY"]} />
              <SelectOption key={3} value={["MAX_LIFESPAN"]} />
              <SelectOption key={4} value={["NO_CACHE"]} />
            </Select>
          )}
        />
      </FormGroup>
      {isEqual(cachePolicyType, ["EVICT_WEEKLY"]) ? (
        <FormGroup
          label={t("evictionDay")}
          labelIcon={
            <HelpItem
              helpText="user-federation-help:evictionDayHelp"
              fieldLabelId="user-federation:evictionDay"
            />
          }
          isRequired
          fieldId="kc-eviction-day"
        >
          <Controller
            name="config.evictionDay[0]"
            defaultValue={"1"}
            control={form.control}
            render={({ onChange, value }) => (
              <Select
                data-testid="cache-day"
                toggleId="kc-eviction-day"
                required
                onToggle={toggleEvictionDay}
                isOpen={isEvictionDayOpen}
                onSelect={(_, value) => {
                  onChange(value as string);
                  toggleEvictionDay();
                }}
                selections={value}
                variant={SelectVariant.single}
              >
                <SelectOption key={0} value="1" isPlaceholder>
                  {t("common:Sunday")}
                </SelectOption>
                <SelectOption key={1} value="2">
                  {t("common:Monday")}
                </SelectOption>
                <SelectOption key={2} value="3">
                  {t("common:Tuesday")}
                </SelectOption>
                <SelectOption key={3} value="4">
                  {t("common:Wednesday")}
                </SelectOption>
                <SelectOption key={4} value="5">
                  {t("common:Thursday")}
                </SelectOption>
                <SelectOption key={5} value="6">
                  {t("common:Friday")}
                </SelectOption>
                <SelectOption key={6} value="7">
                  {t("common:Saturday")}
                </SelectOption>
              </Select>
            )}
          />
        </FormGroup>
      ) : null}
      {isEqual(cachePolicyType, ["EVICT_DAILY"]) ||
      isEqual(cachePolicyType, ["EVICT_WEEKLY"]) ? (
        <>
          <FormGroup
            label={t("evictionHour")}
            labelIcon={
              <HelpItem
                helpText="user-federation-help:evictionHourHelp"
                fieldLabelId="user-federation:evictionHour"
              />
            }
            isRequired
            fieldId="kc-eviction-hour"
          >
            <Controller
              name="config.evictionHour"
              defaultValue={["0"]}
              control={form.control}
              render={({ onChange, value }) => (
                <Select
                  toggleId="kc-eviction-hour"
                  onToggle={toggleEvictionHour}
                  isOpen={isEvictionHourOpen}
                  onSelect={(_, value) => {
                    onChange(value as string);
                    toggleEvictionHour();
                  }}
                  selections={value}
                  variant={SelectVariant.single}
                >
                  {hourOptions}
                </Select>
              )}
            />
          </FormGroup>
          <FormGroup
            label={t("evictionMinute")}
            labelIcon={
              <HelpItem
                helpText="user-federation-help:evictionMinuteHelp"
                fieldLabelId="user-federation:evictionMinute"
              />
            }
            isRequired
            fieldId="kc-eviction-minute"
          >
            <Controller
              name="config.evictionMinute"
              defaultValue={["0"]}
              control={form.control}
              render={({ onChange, value }) => (
                <Select
                  toggleId="kc-eviction-minute"
                  onToggle={toggleEvictionMinute}
                  isOpen={isEvictionMinuteOpen}
                  onSelect={(_, value) => {
                    onChange(value as string);
                    toggleEvictionMinute();
                  }}
                  selections={value}
                  variant={SelectVariant.single}
                >
                  {minuteOptions}
                </Select>
              )}
            />
          </FormGroup>
        </>
      ) : null}
      {isEqual(cachePolicyType, ["MAX_LIFESPAN"]) ? (
        <FormGroup
          label={t("maxLifespan")}
          labelIcon={
            <HelpItem
              helpText="user-federation-help:maxLifespanHelp"
              fieldLabelId="user-federation:maxLifespan"
            />
          }
          fieldId="kc-max-lifespan"
        >
          <Controller
            name="config.maxLifespan[0]"
            defaultValue={0}
            control={form.control}
            render={({ onChange, value }) => {
              const MIN_VALUE = 0;
              const setValue = (newValue: number) =>
                onChange(Math.max(newValue, MIN_VALUE));

              return (
                <NumberInput
                  id="kc-max-lifespan"
                  data-testid="kerberos-cache-lifespan"
                  value={value}
                  min={MIN_VALUE}
                  unit={t("ms")}
                  type="text"
                  onPlus={() => onChange(Number(value) + 1)}
                  onMinus={() => onChange(Number(value) - 1)}
                  onChange={(event) => {
                    const newValue = Number(event.currentTarget.value);
                    setValue(!isNaN(newValue) ? newValue : 0);
                  }}
                />
              );
            }}
          />
        </FormGroup>
      ) : null}
    </>
  );
};

export const SettingsCache = ({
  form,
  showSectionHeading = false,
  showSectionDescription = false,
  unWrap = false,
}: SettingsCacheProps) => {
  const { t } = useTranslation("user-federation");
  const { t: helpText } = useTranslation("user-federation-help");

  return (
    <>
      {showSectionHeading && (
        <WizardSectionHeader
          title={t("cacheSettings")}
          description={helpText("cacheSettingsDescription")}
          showDescription={showSectionDescription}
        />
      )}
      {unWrap ? (
        <CacheFields form={form} />
      ) : (
        <FormAccess role="manage-realm" isHorizontal>
          <CacheFields form={form} />
        </FormAccess>
      )}
    </>
  );
};
