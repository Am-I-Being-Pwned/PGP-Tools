import { useCallback, useEffect, useRef } from "react";

import { useComposeTranslation, useTranslation } from "~/hooks";
import { languageLabel } from "~/lib/ai/languages";
import { applyTextareaEdit } from "~/lib/compose/apply-edit";
import { t } from "~/lib/i18n";
import { toast } from "~/lib/toast";
import type { useWorkspace } from "./useWorkspace";
import type { ComposeTools } from "./WorkspaceInput";

/**
 * Result translation and compose translation for the workspace. The
 * compose undo original is plaintext: wiped at master lock (s.8.11).
 */
export function useWorkspaceTranslation(
  ws: ReturnType<typeof useWorkspace>,
  {
    targetLanguage: translationTargetLanguage,
    aiTranslateEnabled,
    done,
    hasOutputText,
  }: {
    targetLanguage: string;
    aiTranslateEnabled: boolean;
    done: boolean;
    hasOutputText: boolean;
  },
) {
  const s = ws.state;
  const translation = useTranslation({
    getOutput: ws.getOutput,
    outputVersion: s.output.version,
    setTranslation: ws.setTranslation,
    targetLanguage: translationTargetLanguage,
  });

  // Through the textarea's editing path, so mod+Z reverts a translation.
  const { inputElRef, inputChanged } = ws;
  const setComposedText = useCallback(
    (text: string) => {
      const el = inputElRef.current;
      if (
        el &&
        applyTextareaEdit(el, { text, start: text.length, end: text.length })
      ) {
        return;
      }
      inputChanged(text);
    },
    [inputElRef, inputChanged],
  );
  const translatedToastRef = useRef<string | number | null>(null);
  const translatedToastSeq = useRef(0);
  const composeTranslation = useComposeTranslation({
    getInput: ws.getInput,
    setInput: setComposedText,
    readingLanguage: translationTargetLanguage,
    onTranslated: (from, to) => {
      // Fresh id: a toast reusing a leaving one's id is merged into it and leaves with it.
      if (translatedToastRef.current !== null) {
        toast.dismiss(translatedToastRef.current);
      }
      translatedToastRef.current = toast.message(
        t("workspace_compose_translated", {
          from: languageLabel(from),
          to: languageLabel(to),
        }),
        {
          id: `compose-translated-${++translatedToastSeq.current}`,
          duration: 6000,
          action: {
            label: t("workspace_undo"),
            onClick: () => composeTranslation.undo(),
          },
        },
      );
    },
    onStatus: (status) => {
      if (status.kind === "same-language") {
        toast.message(
          t("workspace_compose_same_language", {
            language: languageLabel(status.language),
          }),
          { id: "compose-translate" },
        );
      } else if (status.kind === "unavailable") {
        toast.message(t("workspace_compose_translate_unavailable"), {
          id: "compose-translate",
        });
      } else if (status.kind === "error") {
        toast.error(status.message, { id: "compose-translate" });
      }
    },
  });
  // The undo original is plaintext: wiped at master lock (§8.11), dropped
  // once the user edits past it, cancelled when the box stops composing.
  const { addWiper, getInput } = ws;
  const { forget, noteInputChanged, cancel } = composeTranslation;
  useEffect(() => addWiper(forget), [addWiper, forget]);
  useEffect(() => {
    noteInputChanged(getInput());
  }, [s.input.version, noteInputChanged, getInput]);
  const composeToolsRef = useRef<ComposeTools | null>(null);
  const onToolsReady = useCallback((tools: ComposeTools | null) => {
    composeToolsRef.current = tools;
  }, []);
  // The find bar's highlight mirror holds a copy of the text.
  useEffect(
    () => addWiper(() => composeToolsRef.current?.closeFind()),
    [addWiper],
  );
  const composeCanEdit =
    (s.mode === "encrypt" || s.mode === "sign") &&
    s.files.length === 0 &&
    s.input.key !== "private";
  useEffect(() => {
    if (!composeCanEdit) cancel();
  }, [composeCanEdit, cancel]);
  const translateEnabled =
    aiTranslateEnabled && composeTranslation.status.kind !== "unavailable";
  const resultCanTranslate =
    aiTranslateEnabled &&
    done &&
    hasOutputText &&
    (s.mode === "decrypt" || s.mode === "verify") &&
    translation.status.kind !== "unavailable" &&
    translation.status.kind !== "same-language";

  return {
    translation,
    composeTranslation,
    setComposedText,
    composeToolsRef,
    onToolsReady,
    composeCanEdit,
    translateEnabled,
    resultCanTranslate,
  };
}
