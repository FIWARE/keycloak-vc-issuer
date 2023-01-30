import { CodeEditor, Language } from "@patternfly/react-code-editor";
import { ActionGroup, Button, Form, PageSection } from "@patternfly/react-core";
import type { editor } from "monaco-editor";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAlerts } from "../../components/alert/Alerts";
import { prettyPrintJSON } from "../../util";
import { useUserProfile } from "./UserProfileContext";

export const JsonEditorTab = () => {
  const { config, save, isSaving } = useUserProfile();
  const { t } = useTranslation();
  const { addError } = useAlerts();
  const [editor, setEditor] = useState<editor.IStandaloneCodeEditor>();

  useEffect(() => resetCode(), [config, editor]);

  function resetCode() {
    editor?.setValue(config ? prettyPrintJSON(config) : "");
  }

  function handleSave() {
    const value = editor?.getValue();

    if (!value) {
      return;
    }

    try {
      save(JSON.parse(value));
    } catch (error) {
      addError("realm-settings:invalidJsonError", error);
      return;
    }
  }

  return (
    <PageSection variant="light">
      <CodeEditor
        language={Language.json}
        height="30rem"
        onEditorDidMount={(editor) => setEditor(editor)}
        isLanguageLabelVisible
      />
      <Form>
        <ActionGroup>
          <Button variant="primary" onClick={handleSave} isDisabled={isSaving}>
            {t("common:save")}
          </Button>
          <Button variant="link" onClick={resetCode} isDisabled={isSaving}>
            {t("common:revert")}
          </Button>
        </ActionGroup>
      </Form>
    </PageSection>
  );
};
