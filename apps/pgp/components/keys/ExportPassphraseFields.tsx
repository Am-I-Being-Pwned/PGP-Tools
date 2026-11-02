import { useState } from "react";

import { Block } from "@amibeingpwned/ui/block";
import { Button } from "@amibeingpwned/ui/button";
import { Input } from "@amibeingpwned/ui/input";

import { t } from "../../lib/i18n";
import { validateExportPassphrase } from "./protection-choice";

/** The passphrase pair an export is sealed under, plus the typed confirm
 *  word that unlocks the plaintext escape hatch. */
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

export type ExportPassphrase = ReturnType<typeof useExportPassphrase>;

interface ExportPassphraseFieldsProps {
  fields: ExportPassphrase;
  error?: string | null;
  /** Inline success line (a copy's "copied" note). */
  feedback?: string | null;
  busy: boolean;
  submitLabel: string;
  busyLabel: string;
  onSubmit: () => void;
  /** Offer the unencrypted export, behind typing the confirm word. */
  plaintext?: { warning: string; button: string; onExport: () => void };
}

/** Passphrase + confirm, the encrypted export button, and the plaintext
 *  escape hatch in a block of its own (solid red, never the default). */
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
          // A re-render can drop focus onto the header's Back button
          // before the keypress lands.
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
