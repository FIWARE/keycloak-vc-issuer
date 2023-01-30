import { useTranslation } from "react-i18next";
import { useForm } from "react-hook-form";
import { AlertVariant, Button, Form, FormGroup } from "@patternfly/react-core";
import { CheckIcon, PencilAltIcon, TimesIcon } from "@patternfly/react-icons";

import type CredentialRepresentation from "@keycloak/keycloak-admin-client/lib/defs/credentialRepresentation";
import { useAdminClient } from "../../context/auth/AdminClient";
import { useAlerts } from "../../components/alert/Alerts";
import { KeycloakTextInput } from "../../components/keycloak-text-input/KeycloakTextInput";

type UserLabelForm = {
  userLabel: string;
};

type InlineLabelEditProps = {
  userId: string;
  credential: CredentialRepresentation;
  isEditable: boolean;
  toggle: () => void;
};

export const InlineLabelEdit = ({
  userId,
  credential,
  isEditable,
  toggle,
}: InlineLabelEditProps) => {
  const { t } = useTranslation("users");
  const { register, handleSubmit } = useForm<UserLabelForm>();

  const { adminClient } = useAdminClient();
  const { addAlert, addError } = useAlerts();

  const saveUserLabel = async (userLabel: UserLabelForm) => {
    try {
      await adminClient.users.updateCredentialLabel(
        {
          id: userId,
          credentialId: credential.id!,
        },
        userLabel.userLabel || ""
      );
      addAlert(t("updateCredentialUserLabelSuccess"), AlertVariant.success);
      toggle();
    } catch (error) {
      addError("users:updateCredentialUserLabelError", error);
    }
  };

  return (
    <Form
      isHorizontal
      className="kc-form-userLabel"
      onSubmit={handleSubmit(saveUserLabel)}
    >
      <FormGroup fieldId="kc-userLabel" className="kc-userLabel-row">
        <div className="kc-form-group-userLabel">
          {isEditable ? (
            <>
              <KeycloakTextInput
                name="userLabel"
                data-testid="userLabelFld"
                defaultValue={credential.userLabel}
                ref={register()}
                type="text"
                className="kc-userLabel"
                aria-label={t("userLabel")}
              />
              <div className="kc-userLabel-actionBtns">
                <Button
                  data-testid="editUserLabelAcceptBtn"
                  variant="link"
                  className="kc-editUserLabelAcceptBtn"
                  type="submit"
                  icon={<CheckIcon />}
                />
                <Button
                  data-testid="editUserLabelCancelBtn"
                  variant="link"
                  className="kc-editUserLabel-cancelBtn"
                  onClick={toggle}
                  icon={<TimesIcon />}
                />
              </div>
            </>
          ) : (
            <>
              {credential.userLabel}
              <Button
                aria-label={t("editUserLabel")}
                variant="link"
                className="kc-editUserLabel-btn"
                onClick={toggle}
                data-testid="editUserLabelBtn"
                icon={<PencilAltIcon />}
              />
            </>
          )}
        </div>
      </FormGroup>
    </Form>
  );
};
