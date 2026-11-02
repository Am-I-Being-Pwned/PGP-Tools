import type { RefObject } from "react";
import { DownloadIcon, RotateCcwIcon } from "lucide-react";

import {
  Button,
  OptionBar,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  type ShortcutSpec,
} from "@amibeingpwned/ui";

import { ToggleBadge } from "~/components/shared/ToggleBadge";
import { savePreference, useNav, usePreferences } from "~/hooks";
import { sshPasswordReason } from "~/lib/encrypt-recipients";
import { t } from "~/lib/i18n";
import { requestUnlimitedHistoryStorage } from "~/lib/storage/history";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import { INPUT_CLASS } from "~/lib/utils/styles";
import { withoutHiddenCharacters } from "./hidden-characters";
import { KeySelector } from "./KeySelector";
import type { selectionEngine } from "./recipient-engine";
import { ResultActions } from "./ResultActions";
import type { Workspace } from "./useWorkspace";
import type { WorkspaceFlags } from "./workspace-view";
import { modeLabel } from "./WorkspaceInput";

type Ws = Workspace;
type View = WorkspaceFlags;
type Engine = ReturnType<typeof selectionEngine>;

/** mod+Enter mirrors the main action button. */
export const RUN_SHORTCUT: ShortcutSpec = { mod: true, key: "Enter" };

/** The preference-backed encrypt toggles; the palette runs the same code. */
export function useEncryptToggles(ws: Ws) {
  const resetResults = () => ws.dispatch({ type: "reset-results" });
  return {
    setEncryptToSelf: (checked: boolean) => {
      resetResults();
      void savePreference({ encryptToSelf: checked });
    },
    setAlsoSign: (checked: boolean) => {
      resetResults();
      void savePreference({ signWhenEncrypting: checked });
    },
    setSaveToHistory: (checked: boolean) => {
      void savePreference({ historyEnabled: checked });
      if (checked) void requestUnlimitedHistoryStorage();
    },
  };
}

export function ResetButton({ onClick }: { onClick: () => void }) {
  return (
    <Button
      variant="outline"
      size="icon"
      onClick={onClick}
      title={t("workspace_clear_input_output")}
      aria-label={t("workspace_clear_input_output")}
    >
      <RotateCcwIcon className="h-4 w-4" />
    </Button>
  );
}

/** CRX-or-PGP choice for an extension zip, then the key to sign with. */
export function SignKeyPickers({
  ws,
  v,
  signerInHeader,
  signKeyChoices,
  decryptKeyChoices,
}: {
  ws: Ws;
  v: View;
  signerInHeader: boolean;
  signKeyChoices: ProtectedKeyBlob[];
  decryptKeyChoices: ProtectedKeyBlob[];
}) {
  const { state: s, dispatch, crxKeys } = ws;
  const { showTab } = useNav();
  return (
    <>
      {v.crxSignAvailable && (
        <div className="flex gap-2">
          {(["crx", "pgp"] as const).map((kind) => (
            <Button
              key={kind}
              variant={
                (s.signKindPick ?? "crx") === kind ? "default" : "outline"
              }
              size="sm"
              className="flex-1"
              onClick={() => dispatch({ type: "sign-kind", kind })}
            >
              {kind === "crx"
                ? t("workspace_sign_kind_crx")
                : t("workspace_sign_kind_pgp")}
            </Button>
          ))}
        </div>
      )}

      {v.needsPrivateKey && !v.showCrxSign && !signerInHeader && (
        <KeySelector
          label={
            s.mode === "sign"
              ? t("workspace_sign_with")
              : t("workspace_decrypt_with")
          }
          keys={s.mode === "sign" ? signKeyChoices : decryptKeyChoices}
          selectedKeyId={ws.selectedKeyId}
          onSelect={ws.selectPrivateKey}
          emptyText={t("workspace_no_keys_yet")}
          emptyAction={() => showTab("keys")}
          emptyActionLabel={t("workspace_create_one")}
        />
      )}

      {v.showCrxSign && crxKeys.length > 0 && (
        <div>
          <label className="text-muted-foreground mb-1 block text-xs font-medium">
            {t("workspace_sign_with")}
          </label>
          <Select
            value={ws.crxKeyId ?? ""}
            onValueChange={(id) => dispatch({ type: "crx-key-picked", id })}
          >
            <SelectTrigger className="w-full">
              <SelectValue placeholder={t("workspace_select_signing_key")} />
            </SelectTrigger>
            <SelectContent>
              {crxKeys.map((k) => (
                <SelectItem key={k.extensionId} value={k.extensionId}>
                  {k.label ?? k.extensionId}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}
    </>
  );
}

export function EncryptOptions({
  ws,
  encryptEngine,
  selfExcluded,
}: {
  ws: Ws;
  encryptEngine: Engine;
  selfExcluded: boolean;
}) {
  const { state: s, dispatch, myKeys } = ws;
  const { encryptToSelf, neverCacheKeys, historyEnabled } = usePreferences();
  const { setEncryptToSelf, setSaveToHistory } = useEncryptToggles(ws);
  const { showTab } = useNav();
  const fileCount =
    s.files.length + (s.files.length > 0 && s.input.nonBlank ? 1 : 0);
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <OptionBar className="flex flex-1 [&>*]:flex-auto [&>*]:px-2 [&>*]:text-xs">
          {myKeys.length > 0 && (
            <ToggleBadge
              pressed={encryptToSelf}
              onPressedChange={setEncryptToSelf}
            >
              {t("workspace_toggle_encrypt_to_self")}
            </ToggleBadge>
          )}
          <ToggleBadge
            pressed={ws.passwordReady}
            disabledReason={
              encryptEngine === "ssh" ? sshPasswordReason() : undefined
            }
            onPressedChange={(on) => {
              if (on) {
                dispatch({ type: "password-dialog", open: true });
                dispatch({ type: "reset-results" });
              } else {
                dispatch({ type: "password-set", password: "" });
              }
            }}
          >
            {t("workspace_toggle_password")}
          </ToggleBadge>
          {fileCount > 1 && (
            <ToggleBadge
              pressed={s.zipFiles}
              onPressedChange={(on) => dispatch({ type: "zip-files", on })}
            >
              {t("workspace_toggle_zip_files")}
            </ToggleBadge>
          )}
          {!neverCacheKeys && (
            <ToggleBadge
              pressed={historyEnabled}
              onPressedChange={setSaveToHistory}
            >
              {t("workspace_toggle_save_to_history")}
            </ToggleBadge>
          )}
        </OptionBar>
      </div>
      {encryptToSelf && selfExcluded && (
        <p className="text-muted-foreground pl-2 text-xs">
          {t("workspace_self_excluded_intro")}{" "}
          {encryptEngine === "ssh"
            ? t("workspace_self_excluded_age")
            : t("workspace_self_excluded_pgp")}{" "}
          <button
            type="button"
            onClick={() => showTab("keys")}
            className="text-primary underline"
          >
            {t("workspace_import_one")}
          </button>
        </p>
      )}
    </div>
  );
}

export function PasswordPrompt({
  ws,
  inputRef,
  busy,
  busyLabel,
}: {
  ws: Ws;
  inputRef: RefObject<HTMLInputElement | null>;
  busy: boolean;
  busyLabel: boolean;
}) {
  const { state: s, dispatch } = ws;
  const { prompt } = s;
  if (!prompt) return null;
  return (
    <>
      <div className="flex items-stretch gap-2">
        <input
          ref={inputRef}
          type="password"
          placeholder={
            prompt.kind === "message"
              ? t("workspace_enter_message_password")
              : t("workspace_enter_key_password")
          }
          value={prompt.value}
          onChange={(e) =>
            dispatch({ type: "prompt-typed", value: e.target.value })
          }
          onKeyDown={(e) => {
            if (e.key === "Enter") void ws.submitPassword();
          }}
          className={`${INPUT_CLASS} h-9 flex-1 py-0`}
          autoFocus
        />
        <Button
          size="sm"
          className="h-9 shrink-0"
          onClick={() => void ws.submitPassword()}
          disabled={busy}
        >
          {busyLabel
            ? prompt.kind === "message"
              ? t("workspace_decrypting")
              : t("workspace_unlocking")
            : prompt.kind === "crx" || s.mode === "sign"
              ? t("common_sign")
              : s.mode === "decrypt"
                ? t("common_decrypt")
                : t("workspace_go")}
        </Button>
      </div>
      {prompt.error && <p className="text-bad text-xs">{prompt.error}</p>}
    </>
  );
}

/** The auto-run's size hold, and the hidden-characters stop before signing. */
export function RunNotices({
  ws,
  setComposedText,
}: {
  ws: Ws;
  setComposedText: (text: string) => void;
}) {
  const { run } = ws.state;
  if (run.kind === "held-back") {
    return (
      <p
        data-testid="auto-run-held-back"
        className="text-muted-foreground text-xs"
      >
        {t("workspace_auto_run_too_large")}
      </p>
    );
  }
  if (run.kind !== "hidden-chars") return null;
  // Hidden chars are signed as-is only on an explicit "Sign anyway".
  return (
    <div
      role="alert"
      data-testid="hidden-chars-strip"
      className="text-warn space-y-2 rounded-xl bg-[#252012] px-3 py-2.5 text-xs"
    >
      <p>
        {t("workspace_sign_hidden_chars", {
          chars:
            run.chars.slice(0, 4).join(", ") +
            (run.chars.length > 4 ? ` +${run.chars.length - 4}` : ""),
        })}
      </p>
      <div className="flex gap-2">
        <button
          type="button"
          onClick={ws.signWithHiddenChars}
          className="bg-warn/12 hover:bg-warn/20 rounded-md px-2 py-1 font-medium transition-colors"
        >
          {t("workspace_sign_hidden_chars_anyway")}
        </button>
        <button
          type="button"
          onClick={() => {
            setComposedText(withoutHiddenCharacters(ws.getInput()));
            ws.dispatch({ type: "reset-results" });
          }}
          className="bg-warn/12 hover:bg-warn/20 rounded-md px-2 py-1 font-medium transition-colors"
        >
          {t("workspace_sign_hidden_chars_remove")}
        </button>
      </div>
    </div>
  );
}

/** The bottom row: save a signed CRX, verify a CRX, sign for the Web
 *  Store, or the mode's own action with copy/download once done. */
export function MainActions({
  ws,
  v,
  busyLabel,
  copied,
  onCopy,
  onSaveCrx,
  onRun,
  onReset,
}: {
  ws: Ws;
  v: View;
  busyLabel: boolean;
  copied: boolean;
  onCopy: () => void;
  onSaveCrx: () => void;
  onRun: () => void;
  onReset: () => void;
}) {
  const { state: s } = ws;
  const resetAll = () => ws.dispatch({ type: "reset-all" });
  const { loading, done, crxResult } = v;
  if (s.prompt) return null;
  return (
    <div className="space-y-2">
      {crxResult ? (
        <div className="flex gap-2">
          <Button className="flex-1" onClick={onSaveCrx}>
            <span className="flex items-center gap-2">
              <DownloadIcon className="h-4 w-4" />
              {t("workspace_save_file", { name: crxResult.name })}
            </span>
          </Button>
          <ResetButton onClick={resetAll} />
        </div>
      ) : v.showCrxVerify ? (
        <Button
          className="w-full"
          variant={done ? "outline" : "default"}
          onClick={done ? resetAll : () => void ws.verifyCrxInput()}
          disabled={loading}
        >
          {busyLabel
            ? t("workspace_verifying")
            : done
              ? t("workspace_reset")
              : t("workspace_verify_signature")}
        </Button>
      ) : v.showCrxSign ? (
        <Button
          className="w-full"
          onClick={() => void ws.executeCrxSign()}
          disabled={loading}
        >
          {busyLabel
            ? t("workspace_processing")
            : t("workspace_sign_for_web_store")}
        </Button>
      ) : (
        <div className="flex gap-2">
          {done && s.mode !== "verify" ? (
            <ResultActions
              onDownload={ws.triggerDownload}
              onCopy={v.hasOutputText ? onCopy : undefined}
              copied={copied}
              disabled={loading}
            />
          ) : (
            <Button
              className="flex-1 capitalize"
              onClick={onRun}
              disabled={
                loading ||
                !v.hasInput ||
                (s.mode === "encrypt" && !v.canEncrypt)
              }
              title={
                s.mode === "encrypt" && !v.canEncrypt
                  ? t("workspace_need_recipient_or_password")
                  : undefined
              }
              shortcut={RUN_SHORTCUT}
            >
              {busyLabel
                ? t("workspace_processing")
                : done && s.mode === "verify"
                  ? t("workspace_reset")
                  : modeLabel(s.mode)}
            </Button>
          )}
          {(v.hasInput || done) && !(done && s.mode === "verify") && (
            <ResetButton onClick={onReset} />
          )}
        </div>
      )}
    </div>
  );
}
