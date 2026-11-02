import { forwardRef, useCallback, useEffect, useRef, useState } from "react";
import {
  EraserIcon,
  LockIcon,
  LockOpenIcon,
  PenLineIcon,
  ShieldCheckIcon,
} from "lucide-react";

import {
  ariaKeyShortcuts,
  Block,
  Button,
  isMacPlatform,
  Kbd,
  Segmented,
} from "@amibeingpwned/ui";

import { useFitLevel } from "~/hooks/useFitLevel";
import { MODE_SHORTCUTS } from "~/lib/actions/definitions";
import { applyTextareaEdit } from "~/lib/compose/apply-edit";
import {
  toggleInlineStyle,
  type Edit,
  type InlineStyle,
} from "~/lib/compose/text-format";
import { t, tn } from "~/lib/i18n";
import type { WorkspaceAction } from "~/lib/messages";
import { ComposeToolbar, type ComposeTranslateProps } from "./ComposeToolbar";
import { DetectedKeyBanner } from "./DetectedKeyBanner";
import { DropZone } from "./DropZone";
import { FindReplaceBar } from "./FindReplaceBar";

type Mode = WorkspaceAction;

const MODE_ORDER: Mode[] = ["encrypt", "decrypt", "sign", "verify"];

const MODE_ICONS: Record<Mode, typeof LockIcon> = {
  encrypt: LockIcon,
  decrypt: LockOpenIcon,
  sign: PenLineIcon,
  verify: ShieldCheckIcon,
};

function modeLabelClipped(row: HTMLElement): boolean {
  return Array.from(
    row.querySelectorAll<HTMLElement>('[role="radio"], [role="radio"] > *'),
  ).some((el) => el.scrollWidth > el.clientWidth + 1);
}

/** Localised mode name; read at render time, never at module load. */
export function modeLabel(mode: Mode): string {
  switch (mode) {
    case "encrypt":
      return t("common_encrypt");
    case "decrypt":
      return t("common_decrypt");
    case "sign":
      return t("common_sign");
    case "verify":
      return t("common_verify");
  }
}

interface WorkspaceInputProps {
  mode: Mode;
  onModeChange: (mode: Mode) => void;
  /** UNCONTROLLED: plaintext lives in the DOM node and the workspace's ref,
   *  never in render state (`useWorkspace`). */
  inputElRef: React.MutableRefObject<HTMLTextAreaElement | null>;
  getInput: () => string;
  hasInput: boolean;
  onInputChange: (text: string) => void;
  /** Owned by the parent so the undo buffer sits in the workspace's
   *  wipeable ref, not in a live toast closure. */
  onClearText: () => void;
  files: File[];
  onFileDrop: (files: File[]) => void;
  onRemoveFile: (index: number) => void;
  onClearFiles: () => void;
  publicKeyDetected: boolean;
  inputVersion: number;
  privateKeyDetected: boolean;
  onNavigateToKeys?: (importPrefill?: string) => void;
  onRevealKey?: (keyId: string) => void;
  /** Returns the input unchanged when there is nothing to fix; that is the
   *  signal to leave the browser's own paste alone. */
  onRepairPastedText: (text: string) => string;
  composeTranslate?: ComposeTranslateProps;
  /** Outside the drop target on purpose: a drop on the recipients is not
   *  a message. */
  cardHeader?: React.ReactNode;
  aboveCard?: React.ReactNode;
  onToolsReady?: (tools: ComposeTools | null) => void;
}

export interface ComposeTools {
  applyStyle: (style: InlineStyle) => void;
  openFind: () => void;
  /** Also drops the highlight mirror (master lock). */
  closeFind: () => void;
}

export function WorkspaceInput({
  mode,
  onModeChange,
  inputElRef,
  getInput,
  hasInput,
  onInputChange,
  onClearText,
  files,
  onFileDrop,
  onRemoveFile,
  onClearFiles,
  publicKeyDetected,
  inputVersion,
  privateKeyDetected,
  onNavigateToKeys,
  onRevealKey,
  onRepairPastedText,
  composeTranslate,
  onToolsReady,
  cardHeader,
  aboveCard,
}: WorkspaceInputProps) {
  // Re-arms on each fresh private-key paste, so the mask can't stay off
  // across two separate pastes.
  const [maskIgnored, setMaskIgnored] = useState(false);
  useEffect(() => {
    if (privateKeyDetected) setMaskIgnored(false);
  }, [privateKeyDetected]);

  // Re-seed on every (re)mount: the textarea really unmounts, and an
  // uncontrolled node comes back empty.
  const attachInput = useCallback(
    (el: HTMLTextAreaElement | null) => {
      inputElRef.current = el;
      if (el) el.value = getInput();
    },
    [inputElRef, getInput],
  );

  const composing = mode === "encrypt" || mode === "sign";
  // Encrypting, files are attachments (the message rides as msg.txt);
  // anywhere else staged files replace the text.
  const textareaMounted = files.length === 0 || mode === "encrypt";
  const showTools = composing && !privateKeyDetected && textareaMounted;
  // A number, not the text, in state.
  const [charCount, setCharCount] = useState(0);
  useEffect(() => {
    setCharCount(getInput().length);
  }, [getInput, inputVersion, hasInput]);
  const modeSwitchRef = useRef<HTMLDivElement>(null);
  const modeFit = useFitLevel(modeSwitchRef, 2, [mode], {
    self: true,
    overflows: modeLabelClipped,
  });
  const stripEndRef = useRef<HTMLDivElement>(null);
  const stripLevel = useFitLevel(stripEndRef, 2, [
    showTools,
    hasInput,
    files.length,
    String(charCount).length,
  ]);
  // The nonce makes a second press while open refocus the field.
  const [find, setFind] = useState<{ query: string; nonce: number } | null>(
    null,
  );
  useEffect(() => {
    if (!textareaMounted) setFind(null);
  }, [textareaMounted]);
  const [highlights, setHighlights] = useState<{
    ranges: { start: number; end: number }[];
    current: number;
  } | null>(null);
  const onHighlight = useCallback(
    (ranges: { start: number; end: number }[], current: number) =>
      setHighlights({ ranges, current }),
    [],
  );
  const backdropRef = useRef<HTMLDivElement>(null);
  const syncBackdropScroll = useCallback(() => {
    const el = inputElRef.current;
    const bd = backdropRef.current;
    if (el && bd) {
      bd.scrollTop = el.scrollTop;
      bd.scrollLeft = el.scrollLeft;
    }
  }, [inputElRef]);
  // Never while masked: the mirror would show the hidden private key.
  const painting = find !== null && highlights !== null && !privateKeyDetected;
  useEffect(() => {
    if (painting) syncBackdropScroll();
  }, [painting, highlights, syncBackdropScroll]);

  const openFind = useCallback(() => {
    const el = inputElRef.current;
    const selected = el
      ? el.value.slice(el.selectionStart, el.selectionEnd)
      : "";
    const query = selected.includes("\n") ? "" : selected;
    setFind((prev) => ({
      query: query || (prev?.query ?? ""),
      nonce: (prev?.nonce ?? 0) + 1,
    }));
  }, [inputElRef]);

  /** Native editing path, so edits share the typing undo stack. */
  const applyEdit = useCallback(
    (edit: Edit, focus = true) => {
      const el = inputElRef.current;
      if (!el) return;
      if (!applyTextareaEdit(el, edit, focus)) onInputChange(edit.text);
    },
    [inputElRef, onInputChange],
  );

  const applyStyle = useCallback(
    (style: InlineStyle) => {
      const el = inputElRef.current;
      if (!el) return;
      applyEdit(
        toggleInlineStyle(
          el.value,
          { start: el.selectionStart, end: el.selectionEnd },
          style,
        ),
      );
    },
    [inputElRef, applyEdit],
  );

  const getSelection = useCallback(() => {
    const el = inputElRef.current;
    return el
      ? { start: el.selectionStart, end: el.selectionEnd }
      : { start: 0, end: 0 };
  }, [inputElRef]);

  /** A textarea has no scrollIntoView for a range: the line is estimated. */
  const selectRange = useCallback(
    (start: number, end: number) => {
      const el = inputElRef.current;
      if (!el) return;
      el.setSelectionRange(start, end);
      const line = el.value.slice(0, start).split("\n").length - 1;
      const lineHeight = parseFloat(getComputedStyle(el).lineHeight) || 20;
      const target = line * lineHeight;
      if (target < el.scrollTop || target > el.scrollTop + el.clientHeight) {
        el.scrollTop = Math.max(0, target - el.clientHeight / 2);
      }
    },
    [inputElRef],
  );

  // Shortcuts are dispatched by the action registry via `onToolsReady`.
  const closeFind = useCallback(() => {
    setFind(null);
    setHighlights(null);
  }, []);
  useEffect(() => {
    onToolsReady?.({ applyStyle, openFind, closeFind });
    return () => onToolsReady?.(null);
  }, [onToolsReady, applyStyle, openFind, closeFind]);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3">
      {/* Manual activation: arrowing across must not reset the workspace
          at every mode it passes. */}
      <div ref={modeSwitchRef}>
        <Segmented
          fill={modeFit === 0}
          className={
            modeFit > 0 ? "[&_[role=radio]]:px-2 [&>*]:flex-auto" : undefined
          }
          activation="manual"
          skipTab
          ariaLabel={t("settings_shortcuts_group_modes")}
          value={mode}
          onValueChange={(v) => {
            // Re-pressing the current mode must not reset a finished result.
            if (v !== mode) onModeChange(v);
          }}
          options={MODE_ORDER.map((value, i) => {
            const iconOnly = modeFit === 2 && value !== mode;
            const Icon = MODE_ICONS[value];
            return {
              value,
              ariaLabel: iconOnly ? modeLabel(value) : undefined,
              hintAlign: !iconOnly
                ? undefined
                : i === 0
                  ? "start"
                  : i === MODE_ORDER.length - 1
                    ? "end"
                    : undefined,
              ariaKeyShortcuts: ariaKeyShortcuts(
                MODE_SHORTCUTS[value],
                isMacPlatform(),
              ),
              hint: iconOnly ? (
                <span className="flex items-center gap-1.5">
                  {modeLabel(value)}
                  <Kbd shortcut={MODE_SHORTCUTS[value]} />
                </span>
              ) : (
                <Kbd shortcut={MODE_SHORTCUTS[value]} />
              ),
              label: iconOnly ? (
                <Icon className="h-3.5 w-3.5 shrink-0" />
              ) : (
                <span className="truncate">{modeLabel(value)}</span>
              ),
            };
          })}
        />
      </div>

      {aboveCard}

      <DropZone
        header={cardHeader}
        enabled={!hasInput || mode === "encrypt"}
        acceptTextDrop={!hasInput}
        onTextDrop={onInputChange}
        onFileDrop={onFileDrop}
        activeFiles={files}
        onRemoveFile={onRemoveFile}
        onClearFiles={onClearFiles}
        leading={
          showTools ? (
            <ComposeToolbar
              onStyle={applyStyle}
              onFind={openFind}
              translate={composeTranslate}
            />
          ) : undefined
        }
        trailing={
          showTools || hasInput ? (
            // Too narrow: the count goes first, then Clear text becomes an
            // icon. Never overflow: it shoves the whole card sideways.
            <div ref={stripEndRef} className="flex items-center gap-1">
              {showTools && stripLevel < 1 && (
                <span className="text-muted-foreground px-1.5 font-mono text-[11px] whitespace-nowrap tabular-nums">
                  {tn("workspace_char_count", charCount)}
                </span>
              )}
              {hasInput &&
                (stripLevel < 2 ? (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-muted-foreground hover:text-foreground h-7 px-2 text-xs whitespace-nowrap"
                    onClick={onClearText}
                  >
                    {t("workspace_clear_text")}
                  </Button>
                ) : (
                  <Button
                    variant="ghost"
                    size="sm"
                    aria-label={t("workspace_clear_text")}
                    title={t("workspace_clear_text")}
                    className="text-muted-foreground hover:text-foreground h-7 w-7 px-0"
                    onClick={onClearText}
                  >
                    <EraserIcon className="h-3.5 w-3.5" />
                  </Button>
                ))}
            </div>
          ) : undefined
        }
      >
        {textareaMounted && (
          <Block className="relative flex min-h-0 flex-1">
            {painting && (
              <FindBackdrop
                ref={backdropRef}
                text={getInput()}
                ranges={highlights.ranges}
                current={highlights.current}
              />
            )}
            <textarea
              id="pgp-input"
              aria-label={t("workspace_message_input_aria")}
              ref={attachInput}
              onChange={(e) => {
                onInputChange(e.target.value);
                setCharCount(e.target.value.length);
              }}
              onScroll={painting ? syncBackdropScroll : undefined}
              onPaste={(e) => {
                // The ONE place workspace armor repair happens: on paste,
                // not onChange (which fires for every typed keystroke).
                // Unchanged text falls through to the browser's own paste.
                const pasted = e.clipboardData.getData("text/plain");
                const repaired = onRepairPastedText(pasted);
                if (repaired === pasted) return;
                e.preventDefault();
                // Splice at the caret: replacing the box would silently
                // discard whatever else was there.
                const el = e.currentTarget;
                const { selectionStart: start, selectionEnd: end } = el;
                const next =
                  el.value.slice(0, start) + repaired + el.value.slice(end);
                el.value = next;
                const caret = start + repaired.length;
                el.setSelectionRange(caret, caret);
                onInputChange(next);
              }}
              // Transparent, not absent: the find mirror draws the same 1px.
              className={`placeholder:text-muted-foreground relative z-10 min-h-20 w-full flex-1 resize-none rounded-[inherit] border border-transparent p-3 text-sm focus:border-[rgb(79_193_133/0.35)] focus:outline-none ${
                painting ? "bg-transparent" : "bg-card"
              }`}
              // Shoulder-surfing protection only: the string stays in V8's
              // heap until GC. privateKeyDetected also blocks draft snapshots.
              style={
                privateKeyDetected && !maskIgnored
                  ? ({ WebkitTextSecurity: "disc" } as React.CSSProperties)
                  : undefined
              }
              placeholder={
                mode === "decrypt"
                  ? t("workspace_placeholder_decrypt")
                  : mode === "verify"
                    ? t("workspace_placeholder_verify")
                    : t("workspace_placeholder_compose")
              }
            />
            {find && (
              <div className="absolute top-2 right-2 z-20 w-[min(100%-1rem,22rem)]">
                <FindReplaceBar
                  initialQuery={find.query}
                  focusNonce={find.nonce}
                  getText={() => inputElRef.current?.value ?? getInput()}
                  getSelection={getSelection}
                  select={selectRange}
                  apply={(edit) => applyEdit(edit, false)}
                  textVersion={inputVersion}
                  onHighlight={onHighlight}
                  onClose={() => {
                    setFind(null);
                    setHighlights(null);
                    inputElRef.current?.focus();
                  }}
                />
              </div>
            )}
          </Block>
        )}
      </DropZone>

      {privateKeyDetected && (
        <div
          role="alert"
          className="text-bad space-y-2 rounded-xl bg-[#2a1517] px-3 py-2.5 text-xs"
        >
          <div className="flex items-start justify-between gap-2">
            <p className="font-semibold">
              {t("workspace_private_key_pasted_title")}
            </p>
            {!maskIgnored && (
              <button
                onClick={() => setMaskIgnored(true)}
                className="bg-destructive/12 hover:bg-destructive/20 shrink-0 rounded-md px-2 py-0.5 text-[10px] font-medium tracking-wide uppercase transition-colors"
                title={t("workspace_private_key_show_cleartext")}
              >
                {t("workspace_private_key_ignore")}
              </button>
            )}
          </div>
          <p>{t("workspace_private_key_pasted_body")}</p>
          <div className="flex gap-2 pt-1">
            <button
              onClick={() => onNavigateToKeys?.(getInput())}
              className="bg-destructive/12 hover:bg-destructive/20 rounded-md px-2 py-1 font-medium transition-colors"
            >
              {t("workspace_private_key_import_safely")}
            </button>
            <button
              onClick={() => onInputChange("")}
              className="bg-destructive/12 hover:bg-destructive/20 rounded-md px-2 py-1 font-medium transition-colors"
            >
              {t("workspace_private_key_clear_input")}
            </button>
          </div>
        </div>
      )}

      {publicKeyDetected && (
        <DetectedKeyBanner
          getText={getInput}
          version={inputVersion}
          onImport={(armored) => onNavigateToKeys?.(armored)}
          onReveal={onRevealKey}
          source="pasted"
        />
      )}
    </div>
  );
}

/** Paints find matches under the transparent textarea; box, padding, font
 *  and wrapping must match it exactly. */
const FindBackdrop = forwardRef<
  HTMLDivElement,
  { text: string; ranges: { start: number; end: number }[]; current: number }
>(function FindBackdrop({ text, ranges, current }, ref) {
  const parts: React.ReactNode[] = [];
  let at = 0;
  ranges.forEach((r, i) => {
    if (r.start > at) parts.push(text.slice(at, r.start));
    parts.push(
      <mark
        key={i}
        className={`rounded-sm text-transparent ${
          i === current ? "bg-ring/70" : "bg-ring/30"
        }`}
      >
        {text.slice(r.start, r.end)}
      </mark>,
    );
    at = r.end;
  });
  parts.push(text.slice(at));
  // A trailing newline needs a character after it to take up a line.
  if (text.endsWith("\n")) parts.push("\u200b");
  return (
    <div
      ref={ref}
      aria-hidden
      className="bg-card pointer-events-none absolute inset-0 overflow-hidden rounded-[inherit] border border-transparent p-3 text-sm break-words whitespace-pre-wrap text-transparent"
    >
      {parts}
    </div>
  );
});
