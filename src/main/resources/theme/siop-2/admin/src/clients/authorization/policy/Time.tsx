import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Controller, useFormContext } from "react-hook-form";
import {
  DatePicker,
  Flex,
  FlexItem,
  FormGroup,
  NumberInput,
  Radio,
  Split,
  SplitItem,
  TimePicker,
  ValidatedOptions,
} from "@patternfly/react-core";

import { HelpItem } from "../../../components/help-enabler/HelpItem";

const DATE_TIME_FORMAT = /(\d\d\d\d-\d\d-\d\d)? (\d\d?):(\d\d?)/;
const padDateSegment = (value: number) => value.toString().padStart(2, "0");

const DateTime = ({ name }: { name: string }) => {
  const { control } = useFormContext();

  const parseDate = (value: string, date?: Date): string => {
    if (!date) {
      return value;
    }

    const parts = value.match(DATE_TIME_FORMAT);
    const parsedDate = [
      date.getFullYear(),
      padDateSegment(date.getMonth() + 1),
      padDateSegment(date.getDate()),
    ].join("-");

    return `${parsedDate} ${parts ? parts[2] : "00"}:${
      parts ? parts[3] : "00"
    }:00`;
  };

  const parseTime = (
    value: string,
    hour?: number | null,
    minute?: number | null
  ): string => {
    const parts = value.match(DATE_TIME_FORMAT);
    if (minute !== undefined && minute !== null) {
      return `${parts ? parts[1] : ""} ${hour}:${
        minute < 10 ? `0${minute}` : minute
      }:00`;
    }
    return value;
  };

  return (
    <Controller
      name={name}
      defaultValue=""
      control={control}
      rules={{ required: true }}
      render={({ onChange, value }) => {
        const dateTime = value.match(DATE_TIME_FORMAT) || ["", "", "0", "00"];
        return (
          <Split hasGutter id={name}>
            <SplitItem>
              <DatePicker
                value={dateTime[1]}
                onChange={(_, date) => {
                  onChange(parseDate(value, date));
                }}
              />
            </SplitItem>
            <SplitItem>
              <TimePicker
                time={`${dateTime[2]}:${dateTime[3]}`}
                onChange={(_, hour, minute) =>
                  onChange(parseTime(value, hour, minute))
                }
                is24Hour
              />
            </SplitItem>
          </Split>
        );
      }}
    />
  );
};

type NumberControlProps = {
  name: string;
  min: number;
  max: number;
};

const NumberControl = ({ name, min, max }: NumberControlProps) => {
  const { control } = useFormContext();
  const setValue = (newValue: number) => Math.min(newValue, max);

  return (
    <Controller
      name={name}
      defaultValue=""
      control={control}
      render={({ onChange, value }) => (
        <NumberInput
          id={name}
          value={value}
          min={min}
          max={max}
          onPlus={() => onChange(Number(value) + 1)}
          onMinus={() => onChange(Number(value) - 1)}
          onChange={(event) => {
            const newValue = Number(event.currentTarget.value);
            onChange(setValue(!isNaN(newValue) ? newValue : 0));
          }}
        />
      )}
    />
  );
};

const FromTo = ({ name, ...rest }: NumberControlProps) => {
  const { t } = useTranslation("clients");

  return (
    <FormGroup
      label={t(name)}
      fieldId={name}
      labelIcon={
        <HelpItem
          helpText={`clients-help:${name}`}
          fieldLabelId={`clients:${name}`}
        />
      }
    >
      <Split hasGutter>
        <SplitItem>
          <NumberControl name={name} {...rest} />
        </SplitItem>
        <SplitItem>{t("common:to")}</SplitItem>
        <SplitItem>
          <NumberControl name={`${name}End`} {...rest} />
        </SplitItem>
      </Split>
    </FormGroup>
  );
};

export const Time = () => {
  const { t } = useTranslation("clients");
  const { getValues, errors } = useFormContext();
  const [repeat, setRepeat] = useState(getValues("month"));
  return (
    <>
      <FormGroup
        label={t("repeat")}
        fieldId="repeat"
        labelIcon={
          <HelpItem
            helpText="clients-help:repeat"
            fieldLabelId="clients:repeat"
          />
        }
      >
        <Flex>
          <FlexItem>
            <Radio
              id="notRepeat"
              data-testid="notRepeat"
              isChecked={!repeat}
              name="repeat"
              onChange={() => setRepeat(false)}
              label={t("notRepeat")}
              className="pf-u-mb-md"
            />
          </FlexItem>
          <FlexItem>
            <Radio
              id="repeat"
              data-testid="repeat"
              isChecked={repeat}
              name="repeat"
              onChange={() => setRepeat(true)}
              label={t("repeat")}
              className="pf-u-mb-md"
            />
          </FlexItem>
        </Flex>
      </FormGroup>
      {repeat && (
        <>
          <FromTo name="month" min={1} max={12} />
          <FromTo name="dayMonth" min={1} max={31} />
          <FromTo name="hour" min={0} max={23} />
          <FromTo name="minute" min={0} max={59} />
        </>
      )}
      <FormGroup
        label={t("startTime")}
        fieldId="notBefore"
        labelIcon={
          <HelpItem
            helpText="clients-help:startTime"
            fieldLabelId="clients:startTime"
          />
        }
        isRequired
        helperTextInvalid={t("common:required")}
        validated={
          errors.notBefore ? ValidatedOptions.error : ValidatedOptions.default
        }
      >
        <DateTime name="notBefore" />
      </FormGroup>
      <FormGroup
        label={t("expireTime")}
        fieldId="notOnOrAfter"
        labelIcon={
          <HelpItem
            helpText="clients-help:expireTime"
            fieldLabelId="clients:expireTime"
          />
        }
        isRequired
        helperTextInvalid={t("common:required")}
        validated={
          errors.notOnOrAfter
            ? ValidatedOptions.error
            : ValidatedOptions.default
        }
      >
        <DateTime name="notOnOrAfter" />
      </FormGroup>
    </>
  );
};
