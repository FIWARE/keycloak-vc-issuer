import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useFormContext } from "react-hook-form";
import {
  ActionList,
  ActionListItem,
  Button,
  Flex,
  FlexItem,
  FormGroup,
  TextInput,
} from "@patternfly/react-core";
import { MinusCircleIcon, PlusCircleIcon } from "@patternfly/react-icons";

import type { ComponentProps } from "./components";
import { HelpItem } from "../help-enabler/HelpItem";
import { convertToName } from "./DynamicComponents";
import { KeyValueType } from "../key-value-form/key-value-convert";

type IdKeyValueType = KeyValueType & {
  id: number;
};

const generateId = () => Math.floor(Math.random() * 100);

export const MapComponent = ({ name, label, helpText }: ComponentProps) => {
  const { t } = useTranslation("dynamic");

  const { getValues, setValue, register } = useFormContext();
  const [map, setMap] = useState<IdKeyValueType[]>([]);
  const fieldName = convertToName(name!);

  useEffect(() => {
    register(fieldName);
    const values: KeyValueType[] = JSON.parse(getValues(fieldName) || "[]");
    if (!values.length) {
      values.push({ key: "", value: "" });
    }
    setMap(values.map((value) => ({ ...value, id: generateId() })));
  }, [register, getValues]);

  const update = (val = map) => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    setValue(fieldName, JSON.stringify(val.map(({ id, ...entry }) => entry)));
  };

  const updateKey = (index: number, key: string) => {
    updateEntry(index, { ...map[index], key });
  };

  const updateValue = (index: number, value: string) => {
    updateEntry(index, { ...map[index], value });
  };

  const updateEntry = (index: number, entry: IdKeyValueType) =>
    setMap([...map.slice(0, index), entry, ...map.slice(index + 1)]);

  const remove = (index: number) => {
    const value = [...map.slice(0, index), ...map.slice(index + 1)];
    setMap(value);
    update(value);
  };

  return (
    <FormGroup
      label={t(label!)}
      labelIcon={
        <HelpItem helpText={t(helpText!)} fieldLabelId={`dynamic:${label}`} />
      }
      fieldId={name!}
    >
      <Flex direction={{ default: "column" }}>
        <Flex>
          <FlexItem
            grow={{ default: "grow" }}
            spacer={{ default: "spacerNone" }}
          >
            <strong>{t("common:key")}</strong>
          </FlexItem>
          <FlexItem grow={{ default: "grow" }}>
            <strong>{t("common:value")}</strong>
          </FlexItem>
        </Flex>
        {map.map((attribute, index) => (
          <Flex key={attribute.id} data-testid="row">
            <FlexItem grow={{ default: "grow" }}>
              <TextInput
                name={`${fieldName}[${index}].key`}
                placeholder={t("common:keyPlaceholder")}
                aria-label={t("key")}
                defaultValue={attribute.key}
                data-testid={`${fieldName}[${index}].key`}
                onChange={(value) => updateKey(index, value)}
                onBlur={() => update()}
              />
            </FlexItem>
            <FlexItem
              grow={{ default: "grow" }}
              spacer={{ default: "spacerNone" }}
            >
              <TextInput
                name={`${fieldName}[${index}].value`}
                placeholder={t("common:valuePlaceholder")}
                aria-label={t("common:value")}
                defaultValue={attribute.value}
                data-testid={`${fieldName}[${index}].value`}
                onChange={(value) => updateValue(index, value)}
                onBlur={() => update()}
              />
            </FlexItem>
            <FlexItem>
              <Button
                variant="link"
                title={t("common:removeAttribute")}
                isDisabled={map.length === 1}
                onClick={() => remove(index)}
                data-testid={`${fieldName}[${index}].remove`}
              >
                <MinusCircleIcon />
              </Button>
            </FlexItem>
          </Flex>
        ))}
      </Flex>
      <ActionList>
        <ActionListItem>
          <Button
            data-testid={`${fieldName}-add-row`}
            className="pf-u-px-0 pf-u-mt-sm"
            variant="link"
            icon={<PlusCircleIcon />}
            onClick={() =>
              setMap([...map, { key: "", value: "", id: generateId() }])
            }
          >
            {t("common:addAttribute")}
          </Button>
        </ActionListItem>
      </ActionList>
    </FormGroup>
  );
};
