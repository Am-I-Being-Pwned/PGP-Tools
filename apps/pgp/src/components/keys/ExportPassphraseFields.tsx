import { useState } from "react";

import { Block, Button, Input } from "@amibeingpwned/ui";

import { t } from "~/lib/i18n";
import { validateExportPassphrase } from "./protection-choice";

export function useExportPassphrase() {
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [unsafeConfirm, setUnsafeConfirm] = useState("");
  return {
    passphrase,
    setPassphrase,
    confirmPassphrase,
    setConfirmPassphrase,
    unsafeConfirm,
    setUnsafeConfirm,
    validate: () => validateExportPassphrase(passphrase, confirmPassphrase),
    unsafeConfirmed: unsafeConfirm === t("keygen_confirm_word"),
    clearPassphrase: () => {
      setPassphrase("");
      setConfirmPassphrase("");
    },
    clearUnsafeConfirm: () => setUnsafeConfirm(""),
  };
}

type ExportPassphrase = ReturnType<typeof useExportPassphrase>;

interface ExportPassphraseFieldsProps {
  fields: ExportPassphrase;
  error?: string | null;
  feedback?: string | null;
  busy: boolean;
  submitLabel: string;
  busyLabel: string;
  onSubmit: () => void;
  plaintext?: { warning: string; button: string; onExport: () => void };
}

/** The plaintext escape hatch sits in its own solid-red block, never the default. */
export function ExportPassphraseFields({
  fields,
  error,
  feedback,
  busy,
  submitLabel,
  busyLabel,
  onSubmit,
  plaintext,
}: ExportPassphraseFieldsProps) {
  const confirmWord = t("keygen_confirm_word");
  return (
    <>
      <Input
        type="password"
        autoComplete="new-password"
        placeholder={t("keygen_passphrase_placeholder")}
        value={fields.passphrase}
        onChange={(e) => fields.setPassphrase(e.target.value)}
        autoFocus
      />
      <Input
        type="password"
        autoComplete="new-password"
        placeholder={t("keygen_confirm_passphrase_placeholder")}
        value={fields.confirmPassphrase}
        onChange={(e) => fields.setConfirmPassphrase(e.target.value)}
        onKeyDown={(e) => {
          if (e.key !== "Enter") return;
          // A re-render can drop focus onto Back before the keypress lands.
          e.preventDefault();
          onSubmit();
        }}
      />
      {error && <p className="text-destructive text-xs">{error}</p>}
      {feedback && <p className="text-good text-xs">{feedback}</p>}
      <Button
        className="w-full"
        onClick={onSubmit}
        disabled={busy || !fields.passphrase}
      >
        {busy ? busyLabel : submitLabel}
      </Button>

      {plaintext && (
        <Block className="mt-1 space-y-2 rounded-xl p-3">
          <p className="text-destructive text-[11px]">
            {plaintext.warning} {t("keygen_type_to_confirm_before")}{" "}
            <span className="font-mono font-bold">{confirmWord}</span>{" "}
            {t("keygen_type_to_confirm_after")}
          </p>
          <Input
            type="text"
            autoComplete="off"
            spellCheck={false}
            value={fields.unsafeConfirm}
            onChange={(e) => fields.setUnsafeConfirm(e.target.value)}
            placeholder={confirmWord}
          />
          <Button
            variant="destructive"
            size="sm"
            className="w-full"
            disabled={busy || !fields.unsafeConfirmed}
            onClick={plaintext.onExport}
          >
            {plaintext.button}
          </Button>
        </Block>
      )}
    </>
  );
}
