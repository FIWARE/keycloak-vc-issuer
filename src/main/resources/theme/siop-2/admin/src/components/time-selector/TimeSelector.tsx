import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  DropdownProps,
  Select,
  SelectOption,
  SelectVariant,
  Split,
  SplitItem,
  TextInput,
  TextInputProps,
} from "@patternfly/react-core";

export type Unit = "second" | "minute" | "hour" | "day";

type TimeUnit = { unit: Unit; label: string; multiplier: number };

const allTimes: TimeUnit[] = [
  { unit: "second", label: "times.seconds", multiplier: 1 },
  { unit: "minute", label: "times.minutes", multiplier: 60 },
  { unit: "hour", label: "times.hours", multiplier: 3600 },
  { unit: "day", label: "times.days", multiplier: 86400 },
];

export type TimeSelectorProps = TextInputProps &
  Pick<DropdownProps, "menuAppendTo"> & {
    value: number;
    units?: Unit[];
    onChange: (time: number | string) => void;
    className?: string;
  };

export const getTimeUnit = (value: number) =>
  allTimes.reduce(
    (v, time) =>
      value % time.multiplier === 0 && v.multiplier < time.multiplier
        ? time
        : v,
    allTimes[0]
  );

export const toHumanFormat = (value: number, locale: string) => {
  const timeUnit = getTimeUnit(value);
  const formatter = new Intl.NumberFormat(locale, {
    style: "unit",
    unit: timeUnit.unit,
    unitDisplay: "long",
  });
  return formatter.format(value / timeUnit.multiplier);
};

export const TimeSelector = ({
  value,
  units = ["second", "minute", "hour", "day"],
  onChange,
  className,
  min,
  menuAppendTo,
  ...rest
}: TimeSelectorProps) => {
  const { t } = useTranslation("common");

  const times = useMemo(
    () => units.map((unit) => allTimes.find((time) => time.unit === unit)!),
    [units]
  );

  const defaultMultiplier = useMemo(
    () => allTimes.find((time) => time.unit === units[0])?.multiplier,
    [units]
  );

  const [timeValue, setTimeValue] = useState<"" | number>("");
  const [multiplier, setMultiplier] = useState(defaultMultiplier);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const multiplier = getTimeUnit(value).multiplier;

    if (value) {
      setMultiplier(multiplier);
      setTimeValue(value / multiplier);
    } else {
      setTimeValue(value);
      setMultiplier(defaultMultiplier);
    }
  }, [value]);

  const updateTimeout = (
    timeout: "" | number,
    times: number | undefined = multiplier
  ) => {
    if (timeout !== "") {
      onChange(timeout * (times || 1));
      setTimeValue(timeout);
    } else {
      onChange("");
    }
  };

  return (
    <Split hasGutter className={className}>
      <SplitItem>
        <TextInput
          {...rest}
          type="number"
          aria-label="kc-time"
          min={min || 0}
          value={timeValue}
          className={`${className}-input`}
          onChange={(value) => {
            updateTimeout("" === value ? value : parseInt(value));
          }}
        />
      </SplitItem>
      <SplitItem id={`${className}-select-menu`}>
        <Select
          variant={SelectVariant.single}
          aria-label={t("unitLabel")}
          className={`${className}-select`}
          onSelect={(_, value) => {
            setMultiplier(value as number);
            updateTimeout(timeValue, value as number);
            setOpen(false);
          }}
          menuAppendTo={menuAppendTo}
          selections={[multiplier]}
          onToggle={() => {
            setOpen(!open);
          }}
          isOpen={open}
        >
          {times.map((time) => (
            <SelectOption
              id={time.label}
              key={time.label}
              value={time.multiplier}
            >
              {t(time.label)}
            </SelectOption>
          ))}
        </Select>
      </SplitItem>
    </Split>
  );
};
