import { useTranslation } from "react-i18next";
import {
  DataListItemRow,
  DataListControl,
  DataListDragButton,
  DataListItemCells,
  DataListCell,
  DataListItem,
  DataListToggle,
  Text,
  TextVariants,
  Button,
  Tooltip,
} from "@patternfly/react-core";
import { TrashIcon } from "@patternfly/react-icons";

import type { AuthenticationProviderRepresentation } from "@keycloak/keycloak-admin-client/lib/defs/authenticatorConfigRepresentation";
import type { ExpandableExecution } from "../execution-model";
import type { Flow } from "./modals/AddSubFlowModal";
import { FlowTitle } from "./FlowTitle";
import { FlowRequirementDropdown } from "./FlowRequirementDropdown";
import { ExecutionConfigModal } from "./ExecutionConfigModal";
import { AddFlowDropdown } from "./AddFlowDropdown";
import { EditFlow } from "./EditFlow";

import "./flow-row.css";

type FlowRowProps = {
  builtIn: boolean;
  execution: ExpandableExecution;
  onRowClick: (execution: ExpandableExecution) => void;
  onRowChange: (execution: ExpandableExecution) => void;
  onAddExecution: (
    execution: ExpandableExecution,
    type: AuthenticationProviderRepresentation
  ) => void;
  onAddFlow: (execution: ExpandableExecution, flow: Flow) => void;
  onDelete: (execution: ExpandableExecution) => void;
};

export const FlowRow = ({
  builtIn,
  execution,
  onRowClick,
  onRowChange,
  onAddExecution,
  onAddFlow,
  onDelete,
}: FlowRowProps) => {
  const { t } = useTranslation("authentication");
  const hasSubList = !!execution.executionList?.length;

  return (
    <>
      <DataListItem
        className="keycloak__authentication__flow-item"
        id={execution.id}
        isExpanded={!execution.isCollapsed}
        aria-labelledby={`title-id-${execution.id}`}
      >
        <DataListItemRow
          className="keycloak__authentication__flow-row"
          aria-level={execution.level! + 1}
          role="heading"
          aria-labelledby={execution.id}
        >
          <DataListControl>
            <DataListDragButton aria-label={t("common-help:dragHelp")} />
          </DataListControl>
          {hasSubList && (
            <DataListToggle
              onClick={() => onRowClick(execution)}
              isExpanded={!execution.isCollapsed}
              id={`toggle1-${execution.id}`}
              aria-controls={execution.executionList![0].id}
            />
          )}
          <DataListItemCells
            dataListCells={[
              <DataListCell key={`${execution.id}-name`}>
                {!execution.authenticationFlow && (
                  <FlowTitle
                    id={execution.id}
                    key={execution.id}
                    title={execution.displayName!}
                  />
                )}
                {execution.authenticationFlow && (
                  <>
                    {execution.displayName} <br />{" "}
                    <Text component={TextVariants.small}>
                      {execution.description}
                    </Text>
                  </>
                )}
              </DataListCell>,
              <DataListCell key={`${execution.id}-requirement`}>
                <FlowRequirementDropdown
                  flow={execution}
                  onChange={onRowChange}
                />
              </DataListCell>,
              <DataListCell key={`${execution.id}-config`}>
                {execution.configurable && (
                  <ExecutionConfigModal execution={execution} />
                )}
                {execution.authenticationFlow && !builtIn && (
                  <>
                    <AddFlowDropdown
                      execution={execution}
                      onAddExecution={onAddExecution}
                      onAddFlow={onAddFlow}
                    />
                    <EditFlow execution={execution} onRowChange={onRowChange} />
                  </>
                )}
                {!builtIn && (
                  <Tooltip content={t("common:delete")}>
                    <Button
                      variant="plain"
                      data-testid={`${execution.displayName}-delete`}
                      aria-label={t("common:delete")}
                      onClick={() => onDelete(execution)}
                    >
                      <TrashIcon />
                    </Button>
                  </Tooltip>
                )}
              </DataListCell>,
            ]}
          />
        </DataListItemRow>
      </DataListItem>
      {!execution.isCollapsed &&
        hasSubList &&
        execution.executionList?.map((ex) => (
          <FlowRow
            builtIn={builtIn}
            key={ex.id}
            execution={ex}
            onRowClick={onRowClick}
            onRowChange={onRowChange}
            onAddExecution={onAddExecution}
            onAddFlow={onAddFlow}
            onDelete={onDelete}
          />
        ))}
    </>
  );
};
