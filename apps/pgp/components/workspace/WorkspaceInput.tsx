import { forwardRef, useCallback, useEffect, useRef, useState } from "react";
import {
  EraserIcon,
  LockIcon,
  LockOpenIcon,
  PenLineIcon,
  ShieldCheckIcon,
} from "lucide-react";

import { Block } from "@amibeingpwned/ui/block";
import { Button } from "@amibeingpwned/ui/button";
import { Kbd } from "@amibeingpwned/ui/kbd";
import { ariaKeyShortcuts, isMacPlatform } from "@amibeingpwned/ui/kbd-helpers";
import { Segmented } from "@amibeingpwned/ui/segmented";

import type { Edit, InlineStyle } from "../../lib/compose/text-format";
import type { WorkspaceAction } from "../../lib/messages";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ComposeTranslateProps } from "./ComposeToolbar";
import { useFitLevel } from "../../hooks/useFitLevel";
import { MODE_SHORTCUTS } from "../../lib/actions/definitions";
import { applyTextareaEdit } from "../../lib/compose/apply-edit";
import { toggleInlineStyle } from "../../lib/compose/text-format";
import { t, tn } from "../../lib/i18n";
import { ComposeToolbar } from "./ComposeToolbar";
import { DetectedKeyBanner } from "./DetectedKeyBanner";
import { DropZone } from "./DropZone";
import { FindReplaceBar } from "./FindReplaceBar";

type Mode = WorkspaceAction;

const MODE_ORDER: Mode[] = ["encrypt", "decrypt", "sign", "verify"];

/** Stand-ins for the mode names when the switch is too narrow for them. */
const MODE_ICONS: Record<Mode, typeof LockIcon> = {
  encrypt: LockIcon,
  decrypt: LockOpenIcon,
  sign: PenLineIcon,
  verify: ShieldCheckIcon,
};

/** A mode segment clipping its name. */
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
  /** The message box is UNCONTROLLED: the composed plaintext lives in the
   *  DOM node and in the owning hook's ref, never in render state. See the
   *  input block in `useWorkspaceState` for why. */
  inputElRef: React.MutableRefObject<HTMLTextAreaElement | null>;
  /** Read the current text at the point of use (import prefill). */
  getInput: () => string;
  /** Derived, non-sensitive: the box has at least one character. */
  hasInput: boolean;
  onInputChange: (text: string) => void;
  /** Clear the text with a 4s undo. Owned by the parent so the undo buffer
   *  sits in the workspace's wipeable ref, not in a live toast closure. */
  onClearText: () => void;
  files: File[];
  onFileDrop: (files: File[]) => void;
  onRemoveFile: (index: number) => void;
  onClearFiles: () => void;
  publicKeyDetected: boolean;
  /** Contacts, so the banner can tell "import this" from "you already
   *  have this". */
  contacts: PublicContactKey[];
  /** Bumps whenever the input text changes, so a second pasted key is
   *  identified rather than showing the first one's name. */
  inputVersion: number;
  privateKeyDetected: boolean;
  onNavigateToKeys?: (importPrefill?: string) => void;
  /** Take the user to a key they already hold, highlighted in the list. */
  onRevealKey?: (keyId: string) => void;
  operationDone: boolean;
  onReset: () => void;
  onResetOutput: () => void;
  /** Repair mangled armor in text that ARRIVED (a paste). Returns the
   *  input unchanged when there is nothing to fix, which is the signal
   *  this component uses to leave the browser's own paste alone. */
  onRepairPastedText: (text: string) => string;
  /** Translate-before-sending, when the feature is on and usable. */
  composeTranslate?: ComposeTranslateProps;
  /** The card's top block (the To row, while encrypting). Outside the
   *  drop target on purpose: a drop aimed at the recipient box is not a
   *  message. */
  cardHeader?: React.ReactNode;
  /** Shown between the mode switch and the card (the verify result, so
   *  the verdict reads before the message it is about). */
  aboveCard?: React.ReactNode;
  /** The editing tools, for the action registry (palette + shortcuts).
   *  Called with null on unmount. */
  onToolsReady?: (tools: ComposeTools | null) => void;
}

export interface ComposeTools {
  applyStyle: (style: InlineStyle) => void;
  openFind: () => void;
  /** Close the find bar and drop its highlight mirror (master lock). */
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
  contacts,
  inputVersion,
  privateKeyDetected,
  onNavigateToKeys,
  onRevealKey,
  operationDone,
  onReset,
  onResetOutput,
  onRepairPastedText,
  composeTranslate,
  onToolsReady,
  cardHeader,
  aboveCard,
}: WorkspaceInputProps) {
  // Per-detection mask override. Re-arms whenever a fresh private-key
  // paste is detected so the user can't accidentally leave the mask off
  // across two separate pastes.
  const [maskIgnored, setMaskIgnored] = useState(false);
  useEffect(() => {
    if (privateKeyDetected) setMaskIgnored(false);
  }, [privateKeyDetected]);

  // Callback ref: publish the node to the owning hook and re-seed its value
  // from the ref on every (re)mount. The textarea unmounts whenever files are
  // staged or the full-output view takes over, and an uncontrolled node comes
  // back empty -- re-seeding is what makes the text survive those swaps (the
  // same trick ImportKeyPage uses for its paste box).
  const attachInput = useCallback(
    (el: HTMLTextAreaElement | null) => {
      inputElRef.current = el;
      if (el) el.value = getInput();
    },
    [inputElRef, getInput],
  );

  // ── editing tools (formatting, find & replace, translate) ────────────
  // Prose is composed in encrypt and sign; decrypt and verify take pasted
  // armor, where a bold button is noise. Find still works everywhere.
  const composing = mode === "encrypt" || mode === "sign";
  // Encrypting, files are attachments and the message box stays (the
  // message goes along as msg.txt); anywhere else staged files replace
  // the text.
  const textareaMounted = files.length === 0 || mode === "encrypt";
  const showTools = composing && !privateKeyDetected && textareaMounted;
  // A number for the strip, not the text: re-read from the box on every
  // edit (typed, or set from outside -- `inputVersion` moves then).
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
  // Only the count's digit count moves the strip's width, not every
  // keystroke.
  const stripLevel = useFitLevel(stripEndRef, 2, [
    showTools,
    hasInput,
    files.length,
    String(charCount).length,
  ]);
  // `find` is null when closed; when open it carries the query to start
  // from (the selection at the time of the press) and a nonce so a
  // second press while open refocuses the field, as editors do.
  const [find, setFind] = useState<{ query: string; nonce: number } | null>(
    null,
  );
  useEffect(() => {
    if (!textareaMounted) setFind(null);
  }, [textareaMounted]);
  // The matches the bar wants painted, drawn on a mirror layer under the
  // (transparent) textarea -- see the backdrop below.
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
  // Only while the text is not masked: the mirror would show the
  // private key the mask is hiding.
  const painting = find !== null && highlights !== null && !privateKeyDetected;
  useEffect(() => {
    if (painting) syncBackdropScroll();
  }, [painting, highlights, syncBackdropScroll]);

  const openFind = useCallback(() => {
    const el = inputElRef.current;
    const selected = el
      ? el.value.slice(el.selectionStart, el.selectionEnd)
      : "";
    // A multi-line selection is not a search term.
    const query = selected.includes("\n") ? "" : selected;
    setFind((prev) => ({
      query: query || (prev?.query ?? ""),
      nonce: (prev?.nonce ?? 0) + 1,
    }));
  }, [inputElRef]);

  /** Write an edit into the box through the native editing path, so it
   *  sits on the same undo stack as typing (see `applyTextareaEdit`). */
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

  /** Select a match and scroll it into view. A textarea has no
   *  scrollIntoView for a range, so the line is estimated from the
   *  text before it and the box's line height. */
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

  // Shortcuts (mod+B/I/E, mod+shift+X, mod+F) are dispatched by the action
  // registry, which also lists them in the command palette; the tools are
  // published to it through `onToolsReady`.
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
      {/* Four modes, all visible: one press (or mod+1..4, dispatched by
          the action registry) switches. The hover hint teaches the
          shortcut the old dropdown listed beside each mode -- just the
          shortcut, since the segment already says the mode. Manual
          activation: arrowing across the switch must not act on every
          mode it passes, each of which would reset the workspace.

          Equal segments when the four names fit; segments sized to
          their names when they don't (French, Spanish); and when even
          that clips (German, Russian), the modes you're not on become
          icons and the one you're on keeps its whole word. The hint
          then names the mode as well as its shortcut. */}
      <div ref={modeSwitchRef}>
        <Segmented
          fill={modeFit === 0}
          className={
            modeFit > 0 ? "[&_[role=radio]]:px-2 [&>*]:flex-auto" : undefined
          }
          activation="manual"
          // Out of the Tab order: Tab goes recipients -> message, and the
          // modes have mod+digit shortcuts (and the palette).
          skipTab
          ariaLabel={t("settings_shortcuts_group_modes")}
          value={mode}
          onValueChange={(v) => {
            // A press on the mode already showing is not a change: the
            // dropdown this replaced never fired for it, and the resets
            // below would throw away a finished result.
            if (v === mode) return;
            onModeChange(v);
            if (operationDone) onReset();
            else onResetOutput();
          }}
          options={MODE_ORDER.map((value, i) => {
            const iconOnly = modeFit === 2 && value !== mode;
            const Icon = MODE_ICONS[value];
            return {
              value,
              ariaLabel: iconOnly ? modeLabel(value) : undefined,
              // An icon segment is narrower than its hint (name and
              // shortcut): at either end, keep the hint inside the panel.
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

      {/* The message card is the drop target: the drop zone wraps the
          message block and adds the file list and the bottom strip
          (Browse, or Clear text once there is text). */}
      <DropZone
        header={cardHeader}
        enabled={!hasInput || mode === "encrypt"}
        acceptTextDrop={!hasInput}
        onTextDrop={onInputChange}
        onFileDrop={onFileDrop}
        activeFiles={files}
        onRemoveFile={onRemoveFile}
        onClearFiles={onClearFiles}
        // While composing, the strip is the toolbar: tools on the left,
        // the length on the right. Clear text stays, beside the count.
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
            // When the strip can't hold everything (a long translation,
            // a narrow panel), the count goes first, then Clear text
            // keeps its job as an icon. Never overflowing the card: the
            // stack clips, and an overflowing strip shoved the whole
            // card sideways.
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
                // The ONE place workspace armor repair happens. A paste is
                // the only way mangled armor reaches this box -- nobody
                // hand-types a `\n`-escaped key -- so the repair rides on
                // the paste rather than on `onChange`, which also fires for
                // every keystroke of someone composing a message.
                //
                // Only intercepts when the text actually changed. Otherwise
                // it falls through to the browser's own paste, which knows
                // how to handle undo, IME and multi-range selections better
                // than this handler could.
                const pasted = e.clipboardData.getData("text/plain");
                const repaired = onRepairPastedText(pasted);
                if (repaired === pasted) return;
                e.preventDefault();
                // Splice at the caret rather than replacing the box: a paste
                // into a selection replaces that selection, and a paste with
                // the caret mid-text inserts there. Clobbering the whole
                // value would silently discard whatever else was staged.
                const el = e.currentTarget;
                // Non-null on a textarea (the `?? length` fallback the DOM
                // types once needed is gone), so read them straight.
                const { selectionStart: start, selectionEnd: end } = el;
                const next =
                  el.value.slice(0, start) + repaired + el.value.slice(end);
                el.value = next;
                const caret = start + repaired.length;
                el.setSelectionRange(caret, caret);
                onInputChange(next);
              }}
              // The border is transparent, not absent: the find mirror
              // below draws the same 1px so every character lines up.
              className={`placeholder:text-muted-foreground relative z-10 min-h-20 w-full flex-1 resize-none rounded-[inherit] border border-transparent p-3 text-sm focus:border-[rgb(79_193_133/0.35)] focus:outline-none ${
                painting ? "bg-transparent" : "bg-card"
              }`}
              // Visually mask armored private-key material. NOTE: this is
              // shoulder-surfing protection only; the string still lives in
              // V8's heap until GC. The privateKeyDetected flag elsewhere
              // also blocks draft-snapshotting this content.
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
          contacts={contacts}
          onImport={(armored) => onNavigateToKeys?.(armored)}
          onReveal={onRevealKey}
          source="pasted"
        />
      )}
    </div>
  );
}

/**
 * The mirror layer that paints find matches. Same box, padding, font and
 * wrapping as the textarea so every character lands in the same place;
 * the text itself is transparent and only the marks show through the
 * textarea above (which goes transparent while this is mounted). Scroll
 * is mirrored by the owner on the textarea's scroll events.
 */
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
  // A trailing newline needs a character after it to take up a line,
  // exactly as the textarea's caret does.
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
