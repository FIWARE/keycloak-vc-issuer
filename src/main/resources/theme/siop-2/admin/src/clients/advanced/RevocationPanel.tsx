import { useEffect, useRef } from "react";
import { Link } from "react-router-dom-v5-compat";
import { Trans, useTranslation } from "react-i18next";
import { useFormContext } from "react-hook-form";
import {
  FormGroup,
  InputGroup,
  Button,
  ActionGroup,
  Tooltip,
  Text,
} from "@patternfly/react-core";

import { AdvancedProps, parseResult } from "../AdvancedTab";
import { useAlerts } from "../../components/alert/Alerts";
import { FormAccess } from "../../components/form-access/FormAccess";
import { HelpItem } from "../../components/help-enabler/HelpItem";
import { KeycloakTextInput } from "../../components/keycloak-text-input/KeycloakTextInput";
import { useAdminClient } from "../../context/auth/AdminClient";
import { useRealm } from "../../context/realm-context/RealmContext";
import { toClient } from "../routes/Client";
import useFormatDate, { FORMAT_DATE_AND_TIME } from "../../utils/useFormatDate";

export const RevocationPanel = ({
  save,
  client: { id, adminUrl, access },
}: AdvancedProps) => {
  const revocationFieldName = "notBefore";
  const pushRevocationButtonRef = useRef<HTMLElement>();

  const { t } = useTranslation("clients");
  const { adminClient } = useAdminClient();
  const { realm } = useRealm();
  const { addAlert } = useAlerts();
  const formatDate = useFormatDate();

  const { getValues, setValue, register } = useFormContext();

  const setNotBefore = (time: number, messageKey: string) => {
    setValue(revocationFieldName, time);
    save({ messageKey });
  };

  useEffect(() => {
    register(revocationFieldName);
  }, [register]);

  const getNotBeforeValue = () => {
    const date = getValues(revocationFieldName);
    if (date > 0) {
      return formatDate(new Date(date * 1000), FORMAT_DATE_AND_TIME);
    } else {
      return t("common:none");
    }
  };

  const push = async () => {
    const result = await adminClient.clients.pushRevocation({
      id: id!,
    });
    parseResult(result, "notBeforePush", addAlert, t);
  };

  return (
    <>
      <Text className="pf-u-pb-lg">
        <Trans i18nKey="clients-help:notBeforeIntro">
          In order to successfully push setup url on
          <Link to={toClient({ realm, clientId: id!, tab: "settings" })}>
            {t("settings")}
          </Link>
          tab
        </Trans>
      </Text>
      <FormAccess
        role="manage-clients"
        fineGrainedAccess={access?.configure}
        isHorizontal
      >
        <FormGroup
          label={t("notBefore")}
          fieldId="kc-not-before"
          labelIcon={
            <HelpItem
              helpText="clients-help:notBefore"
              fieldLabelId="clients:notBefore"
            />
          }
        >
          <InputGroup>
            <KeycloakTextInput
              type="text"
              id="kc-not-before"
              name="notBefore"
              isReadOnly
              value={getNotBeforeValue()}
            />
            <Button
              id="setToNow"
              variant="control"
              onClick={() => {
                setNotBefore(Date.now() / 1000, "notBeforeSetToNow");
              }}
            >
              {t("setToNow")}
            </Button>
            <Button
              id="clear"
              variant="control"
              onClick={() => {
                setNotBefore(0, "notBeforeNowClear");
              }}
            >
              {t("clear")}
            </Button>
          </InputGroup>
        </FormGroup>
        <ActionGroup>
          {!adminUrl && (
            <Tooltip
              reference={pushRevocationButtonRef}
              content={t("clients-help:notBeforeTooltip")}
            />
          )}
          <Button
            id="push"
            variant="secondary"
            onClick={push}
            isAriaDisabled={!adminUrl}
            ref={pushRevocationButtonRef}
          >
            {t("push")}
          </Button>
        </ActionGroup>
      </FormAccess>
    </>
  );
};
