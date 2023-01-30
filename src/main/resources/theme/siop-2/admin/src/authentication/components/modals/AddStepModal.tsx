import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Button,
  ButtonVariant,
  Form,
  Modal,
  ModalVariant,
  PageSection,
  Radio,
} from "@patternfly/react-core";
import type { AuthenticationProviderRepresentation } from "@keycloak/keycloak-admin-client/lib/defs/authenticatorConfigRepresentation";

import { PaginatingTableToolbar } from "../../../components/table-toolbar/PaginatingTableToolbar";
import { useAdminClient, useFetch } from "../../../context/auth/AdminClient";
import useLocaleSort, { mapByKey } from "../../../utils/useLocaleSort";
import { providerConditionFilter } from "../../FlowDetails";

type AuthenticationProviderListProps = {
  list?: AuthenticationProviderRepresentation[];
  setValue: (provider?: AuthenticationProviderRepresentation) => void;
};

const AuthenticationProviderList = ({
  list,
  setValue,
}: AuthenticationProviderListProps) => {
  return (
    <PageSection variant="light" className="pf-u-py-lg">
      <Form isHorizontal>
        {list?.map((provider) => (
          <Radio
            id={provider.id!}
            key={provider.id}
            name="provider"
            label={provider.displayName}
            data-testid={provider.id}
            description={provider.description}
            onChange={() => {
              setValue(provider);
            }}
          />
        ))}
      </Form>
    </PageSection>
  );
};

export type FlowType = "client" | "form" | "basic" | "condition" | "subFlow";

type AddStepModalProps = {
  name: string;
  type: FlowType;
  onSelect: (value?: AuthenticationProviderRepresentation) => void;
};

export const AddStepModal = ({ name, type, onSelect }: AddStepModalProps) => {
  const { t } = useTranslation("authentication");
  const { adminClient } = useAdminClient();

  const [value, setValue] = useState<AuthenticationProviderRepresentation>();
  const [providers, setProviders] =
    useState<AuthenticationProviderRepresentation[]>();
  const [max, setMax] = useState(10);
  const [first, setFirst] = useState(0);
  const [search, setSearch] = useState("");
  const localeSort = useLocaleSort();

  useFetch(
    async () => {
      switch (type) {
        case "client":
          return adminClient.authenticationManagement.getClientAuthenticatorProviders();
        case "form":
          return adminClient.authenticationManagement.getFormActionProviders();
        case "condition": {
          const providers =
            await adminClient.authenticationManagement.getAuthenticatorProviders();
          return providers.filter(providerConditionFilter);
        }
        case "basic":
        default: {
          const providers =
            await adminClient.authenticationManagement.getAuthenticatorProviders();
          return providers.filter((p) => !providerConditionFilter(p));
        }
      }
    },
    (providers) => setProviders(providers),
    []
  );

  const page = useMemo(
    () =>
      localeSort(providers ?? [], mapByKey("displayName"))
        .filter(
          (p) =>
            p.displayName?.includes(search) || p.description?.includes(search)
        )
        .slice(first, first + max + 1),
    [providers, search, first, max]
  );

  return (
    <Modal
      variant={ModalVariant.medium}
      isOpen={true}
      title={t("addStepTo", { name })}
      onClose={() => onSelect()}
      actions={[
        <Button
          id="modal-add"
          data-testid="modal-add"
          key="add"
          onClick={() => onSelect(value)}
        >
          {t("common:add")}
        </Button>,
        <Button
          data-testid="cancel"
          id="modal-cancel"
          key="cancel"
          variant={ButtonVariant.link}
          onClick={() => {
            onSelect();
          }}
        >
          {t("common:cancel")}
        </Button>,
      ]}
    >
      {providers && providers.length > max && (
        <PaginatingTableToolbar
          count={page.length || 0}
          first={first}
          max={max}
          onNextClick={setFirst}
          onPreviousClick={setFirst}
          onPerPageSelect={(first, max) => {
            setFirst(first);
            setMax(max);
          }}
          inputGroupName="search"
          inputGroupPlaceholder={t("common:search")}
          inputGroupOnEnter={setSearch}
        >
          <AuthenticationProviderList list={page} setValue={setValue} />
        </PaginatingTableToolbar>
      )}
      {providers && providers.length <= max && (
        <AuthenticationProviderList list={providers} setValue={setValue} />
      )}
    </Modal>
  );
};
