import { useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Button,
  Flex,
  FlexItem,
  Title,
  TitleSizes,
} from "@patternfly/react-core";

import type AuthenticationFlowRepresentation from "@keycloak/keycloak-admin-client/lib/defs/authenticationFlowRepresentation";
import type { AuthenticationProviderRepresentation } from "@keycloak/keycloak-admin-client/lib/defs/authenticatorConfigRepresentation";
import { ListEmptyState } from "../components/list-empty-state/ListEmptyState";
import { AddStepModal } from "./components/modals/AddStepModal";
import { AddSubFlowModal, Flow } from "./components/modals/AddSubFlowModal";

import "./empty-execution-state.css";

const SECTIONS = ["addExecution", "addSubFlow"] as const;
type SectionType = typeof SECTIONS[number] | undefined;

type EmptyExecutionStateProps = {
  flow: AuthenticationFlowRepresentation;
  onAddExecution: (type: AuthenticationProviderRepresentation) => void;
  onAddFlow: (flow: Flow) => void;
};

export const EmptyExecutionState = ({
  flow,
  onAddExecution,
  onAddFlow,
}: EmptyExecutionStateProps) => {
  const { t } = useTranslation("authentication");
  const [show, setShow] = useState<SectionType>();

  return (
    <>
      {show === "addExecution" && (
        <AddStepModal
          name={flow.alias!}
          type={flow.providerId === "client-flow" ? "client" : "basic"}
          onSelect={(type) => {
            if (type) {
              onAddExecution(type);
            }
            setShow(undefined);
          }}
        />
      )}
      {show === "addSubFlow" && (
        <AddSubFlowModal
          name={flow.alias!}
          onCancel={() => setShow(undefined)}
          onConfirm={(newFlow) => {
            onAddFlow(newFlow);
            setShow(undefined);
          }}
        />
      )}
      <ListEmptyState
        message={t("emptyExecution")}
        instructions={t("emptyExecutionInstructions")}
      />

      <div className="keycloak__empty-execution-state__block">
        {SECTIONS.map((section) => (
          <Flex key={section} className="keycloak__empty-execution-state__help">
            <FlexItem flex={{ default: "flex_1" }}>
              <Title headingLevel="h3" size={TitleSizes.md}>
                {t(`${section}Title`)}
              </Title>
              <p>{t(`authentication-help:${section}`)}</p>
            </FlexItem>
            <Flex alignSelf={{ default: "alignSelfCenter" }}>
              <FlexItem>
                <Button
                  data-testid={section}
                  variant="tertiary"
                  onClick={() => setShow(section)}
                >
                  {t(section)}
                </Button>
              </FlexItem>
            </Flex>
          </Flex>
        ))}
      </div>
    </>
  );
};
