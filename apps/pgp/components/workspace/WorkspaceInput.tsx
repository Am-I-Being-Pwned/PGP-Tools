import { forwardRef, useCallback, useEffect, useRef, useState } from "react";

import { Button } from "@amibeingpwned/ui/button";
import { ariaKeyShortcuts, isMacPlatform, Kbd } from "@amibeingpwned/ui/kbd";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@amibeingpwned/ui/select";

import type { Edit, InlineStyle } from "../../lib/compose/text-format";
import type { WorkspaceAction } from "../../lib/messages";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ComposeTranslateProps } from "./ComposeToolbar";
import { MODE_SHORTCUTS } from "../../lib/actions/definitions";
import { applyTextareaEdit } from "../../lib/compose/apply-edit";
import { toggleInlineStyle } from "../../lib/compose/text-format";
import { ComposeToolbar } from "./ComposeToolbar";
import { DetectedKeyBanner } from "./DetectedKeyBanner";
import { DropZone } from "./DropZone";
import { FindReplaceBar } from "./FindReplaceBar";

type Mode = WorkspaceAction;

const MODE_ITEMS: { value: Mode; label: string }[] = [
  { value: "encrypt", label: "Encrypt" },
  { value: "decrypt", label: "Decrypt" },
  { value: "sign", label: "Sign" },
  { value: "verify", label: "Verify" },
];

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
  const textareaMounted = files.length === 0;
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
      <Select
        value={mode}
        onValueChange={(v) => {
          onModeChange(v as Mode);
          if (operationDone) onReset();
          else onResetOutput();
        }}
      >
        <SelectTrigger>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {MODE_ITEMS.map(({ value, label }) => (
            <SelectItem
              key={value}
              className="focus:bg-border/70 cursor-pointer"
              value={value}
              aria-keyshortcuts={ariaKeyShortcuts(
                MODE_SHORTCUTS[value],
                isMacPlatform(),
              )}
              trailing={
                <Kbd
                  shortcut={MODE_SHORTCUTS[value]}
                  className="text-muted-foreground ml-auto pl-4"
                />
              }
            >
              {label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      {hasInput ? (
        <div className="border-border shrink-0 rounded-lg border-2 border-dashed p-5 text-center">
          <p className="text-muted-foreground mb-2 text-sm">
            Text entered below
          </p>
          <Button variant="outline" size="sm" onClick={onClearText}>
            Clear text
          </Button>
        </div>
      ) : (
        <DropZone
          onTextDrop={onInputChange}
          onFileDrop={onFileDrop}
          activeFiles={files}
          onRemoveFile={onRemoveFile}
          onClearFiles={onClearFiles}
        />
      )}

      {textareaMounted && (
        <div className="relative flex min-h-0 flex-1">
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
            aria-label="Message input"
            ref={attachInput}
            onChange={(e) => onInputChange(e.target.value)}
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
            className={`border-border placeholder:text-muted-foreground focus:ring-ring relative z-10 min-h-20 w-full flex-1 resize-none rounded-md border p-3 text-sm focus:ring-2 focus:outline-none ${
              painting ? "bg-transparent" : "bg-background"
            } ${composing && !privateKeyDetected ? "pb-12" : ""}`}
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
                ? "Paste the encrypted message you received..."
                : mode === "verify"
                  ? "Paste the signed message to check..."
                  : "Type or paste your message..."
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
          {composing && !privateKeyDetected && (
            <div className="pointer-events-none absolute right-2 bottom-2 z-20">
              <ComposeToolbar
                onStyle={applyStyle}
                onFind={openFind}
                translate={composeTranslate}
              />
            </div>
          )}
        </div>
      )}

      {privateKeyDetected && (
        <div
          role="alert"
          className="border-destructive bg-destructive/10 text-destructive space-y-2 rounded-md border px-3 py-2 text-xs"
        >
          <div className="flex items-start justify-between gap-2">
            <p className="font-semibold">
              This looks like a private key. Don't paste private keys here.
            </p>
            {!maskIgnored && (
              <button
                onClick={() => setMaskIgnored(true)}
                className="border-destructive/40 hover:bg-destructive/20 shrink-0 rounded border px-2 py-0.5 text-[10px] font-medium tracking-wide uppercase"
                title="Show the pasted text in cleartext"
              >
                Ignore
              </button>
            )}
          </div>
          <p>
            The Encrypt/Decrypt box isn't a safe place for secret key material.
            Use the Import flow so the key is loaded into the secure store and
            kept out of any draft snapshots.
          </p>
          <div className="flex gap-2 pt-1">
            <button
              onClick={() => onNavigateToKeys?.(getInput())}
              className="border-destructive/40 hover:bg-destructive/20 rounded border px-2 py-1 font-medium"
            >
              Import this key safely
            </button>
            <button
              onClick={() => onInputChange("")}
              className="border-destructive/40 hover:bg-destructive/20 rounded border px-2 py-1 font-medium"
            >
              Clear input
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
      className="bg-background pointer-events-none absolute inset-0 overflow-hidden rounded-md border border-transparent p-3 text-sm break-words whitespace-pre-wrap text-transparent"
    >
      {parts}
    </div>
  );
});
