import { useEffect, useMemo, useRef, useState } from "react";
import {
  ChevronDownIcon,
  ChevronRightIcon,
  ChevronUpIcon,
  XIcon,
} from "lucide-react";

import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";
import {
  formatShortcutTitle,
  isMacPlatform,
} from "@amibeingpwned/ui/kbd-helpers";

import type { Edit } from "../../lib/compose/text-format";
import {
  findAll,
  nextMatchIndex,
  prevMatchIndex,
  replaceAll,
  replaceAt,
} from "../../lib/compose/text-format";
import { t } from "../../lib/i18n";
import { matchesShortcut } from "../../lib/shortcuts";
import { INPUT_CLASS } from "../../lib/utils/styles";

/** mod+Enter anywhere in the bar replaces every match. The same combo
 *  is the workspace's "run" shortcut, so the bar must swallow it
 *  whether or not the replace row is open: Encrypting the message from
 *  inside a find field is never what was meant. */
const REPLACE_ALL_SHORTCUT: ShortcutSpec = { mod: true, key: "Enter" };

interface FindReplaceBarProps {
  /** What the field starts with: the box's selection when opened. */
  initialQuery: string;
  /** Bumps when the open shortcut is pressed while already open, to
   *  refocus (and reselect) the field. */
  focusNonce: number;
  /** Read the box's current text at the point of use. */
  getText: () => string;
  /** Where the caret / selection is right now, so "next" starts there. */
  getSelection: () => { start: number; end: number };
  /** Select a range in the box (and scroll it into view). */
  select: (start: number, end: number) => void;
  /** Write an edit back: text plus the selection to leave. */
  apply: (edit: Edit) => void;
  /** Bumps whenever the text changes, so the count stays honest while
   *  the user keeps typing with the bar open. */
  textVersion: number;
  /** Every match as a range plus which one is current, for the owner to
   *  paint. A textarea only paints its own selection while focused, and
   *  focus is in this bar, so the highlighting has to be drawn outside. */
  onHighlight: (
    ranges: { start: number; end: number }[],
    current: number,
  ) => void;
  onClose: () => void;
}

/**
 * Find & replace, floating at the top of the message box.
 *
 * A textarea cannot highlight matches, so the current match is shown by
 * SELECTING it -- the same thing every plain-text editor's find does --
 * and the count inside the field ("2 of 5") carries the rest. Enter
 * steps forward, Shift+Enter back, Escape closes. Replace is a second
 * row behind a chevron: finding is what people open this for; once it
 * is open, Tab goes field to field (Find, Replace, then the replace
 * buttons) and mod+Enter replaces all. The bar
 * floats over the top-right of the box, slightly translucent, so opening
 * it never reflows the message and the text stays readable beneath it.
 */
export function FindReplaceBar({
  initialQuery,
  focusNonce,
  getText,
  getSelection,
  select,
  apply,
  textVersion,
  onHighlight,
  onClose,
}: FindReplaceBarProps) {
  const [query, setQuery] = useState(initialQuery);
  const [replacement, setReplacement] = useState("");
  const [caseSensitive, setCaseSensitive] = useState(false);
  // Find is what the bar is for; replace is a row the user opens.
  const [showReplace, setShowReplace] = useState(false);
  // Index into `matches` of the one currently selected; -1 for none.
  const [current, setCurrent] = useState(-1);
  const findRef = useRef<HTMLInputElement>(null);

  const matches = useMemo(
    () => findAll(getText(), query, { caseSensitive }),
    // `textVersion` is the dependency that makes `getText()` fresh.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [getText, query, caseSensitive, textVersion],
  );

  useEffect(() => {
    findRef.current?.focus();
    findRef.current?.select();
  }, [focusNonce]);

  // A re-press with a new selection replaces the query.
  useEffect(() => {
    if (initialQuery) setQuery(initialQuery);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusNonce]);

  // A new query (or edited text) re-anchors on the first match at or
  // after the caret, so typing a search lands on the nearest hit rather
  // than jumping to the top of the message.
  useEffect(() => {
    if (matches.length === 0) {
      setCurrent(-1);
      return;
    }
    const i = nextMatchIndex(matches, getSelection().start);
    setCurrent(i);
    select(matches[i], matches[i] + query.length);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [matches]);

  useEffect(() => {
    onHighlight(
      matches.map((m) => ({ start: m, end: m + query.length })),
      current,
    );
  }, [matches, current, query.length, onHighlight]);

  const step = (dir: 1 | -1) => {
    if (matches.length === 0) return;
    const { start, end } = getSelection();
    const i =
      dir === 1 ? nextMatchIndex(matches, end) : prevMatchIndex(matches, start);
    setCurrent(i);
    select(matches[i], matches[i] + query.length);
  };

  const replaceCurrent = () => {
    if (current < 0 || matches.length === 0) return;
    const edit = replaceAt(getText(), matches[current], query, replacement);
    apply(edit);
    // The next match after the replacement is where the eye is.
    setTimeout(() => step(1), 0);
  };

  const replaceEvery = () => {
    if (matches.length === 0) return;
    const { text } = replaceAll(getText(), query, replacement, {
      caseSensitive,
    });
    const { start } = getSelection();
    apply({ text, start, end: start });
  };

  const onFindKey = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      step(e.shiftKey ? -1 : 1);
    }
  };
  const onBarKey = (e: React.KeyboardEvent) => {
    if (matchesShortcut(e.nativeEvent, REPLACE_ALL_SHORTCUT, isMacPlatform())) {
      e.preventDefault();
      e.stopPropagation();
      if (showReplace) replaceEvery();
      return;
    }
    if (e.key === "Escape") {
      // Ours, not the workspace's Escape layers (which read
      // `defaultPrevented`).
      e.preventDefault();
      e.stopPropagation();
      onClose();
    }
  };

  const count =
    query.length === 0
      ? ""
      : matches.length === 0
        ? "0"
        : `${current + 1}/${matches.length}`;

  return (
    <div
      role="search"
      aria-label={t("workspace_find_replace")}
      onKeyDown={onBarKey}
      // Three columns, each stacking its own rows (toggle | fields |
      // buttons) rather than one row-major grid, so the two text fields
      // are adjacent in the DOM and Tab moves Find -> Replace -> replace
      // buttons instead of detouring through the find row's icons.
      // Every cell is h-8 with the same gap, so the rows line up.
      className="border-border bg-background/80 flex items-start gap-x-1 rounded-md border p-1.5 shadow-md backdrop-blur"
    >
      <button
        type="button"
        aria-label={
          showReplace
            ? t("workspace_find_hide_replace")
            : t("workspace_find_show_replace")
        }
        aria-expanded={showReplace}
        title={
          showReplace
            ? t("workspace_find_hide_replace")
            : t("workspace_replace")
        }
        onClick={() => setShowReplace((v) => !v)}
        className="text-muted-foreground hover:text-foreground hover:bg-border/70 flex h-8 w-6 shrink-0 items-center justify-center rounded transition-colors"
      >
        {showReplace ? (
          <ChevronDownIcon className="h-4 w-4" />
        ) : (
          <ChevronRightIcon className="h-4 w-4" />
        )}
      </button>
      <div className="flex min-w-0 flex-1 flex-col gap-y-1.5">
        <div className="relative min-w-0">
          <input
            ref={findRef}
            type="text"
            aria-label={t("workspace_find_label")}
            placeholder={t("workspace_find_label")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onFindKey}
            className={`${INPUT_CLASS} h-8 w-full py-0 pr-16 text-xs`}
          />
          <span
            className="text-muted-foreground pointer-events-none absolute inset-y-0 right-2 flex items-center text-[11px] tabular-nums"
            aria-live="polite"
          >
            {count}
          </span>
        </div>
        {showReplace && (
          <input
            type="text"
            aria-label={t("workspace_replace_with")}
            placeholder={t("workspace_replace_with")}
            value={replacement}
            onChange={(e) => setReplacement(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.metaKey && !e.ctrlKey) {
                e.preventDefault();
                replaceCurrent();
              }
            }}
            className={`${INPUT_CLASS} h-8 min-w-0 py-0 text-xs`}
          />
        )}
      </div>
      {/* Rendered bottom-up (flex-col-reverse): the replace buttons come
          FIRST in the DOM, so Tab from the Replace field reaches them
          before the find row's icons, while they still draw beneath. */}
      <div className="flex w-30 shrink-0 flex-col-reverse gap-y-1.5">
        {showReplace && (
          <div className="flex items-center justify-end gap-1">
            <TextButton
              label={t("workspace_replace")}
              disabled={current < 0}
              onClick={replaceCurrent}
            />
            <TextButton
              label={t("workspace_replace_all_short")}
              ariaLabel={t("workspace_replace_all")}
              title={t("workspace_replace_all_shortcut", {
                shortcut: formatShortcutTitle(
                  REPLACE_ALL_SHORTCUT,
                  isMacPlatform(),
                ),
              })}
              disabled={matches.length === 0}
              onClick={replaceEvery}
            />
          </div>
        )}
        <div className="flex items-center justify-end gap-0.5">
          <button
            type="button"
            aria-pressed={caseSensitive}
            aria-label={t("workspace_match_case")}
            title={t("workspace_match_case")}
            onClick={() => setCaseSensitive((v) => !v)}
            className={`hover:text-foreground h-8 w-7 shrink-0 rounded font-mono text-[11px] transition-colors ${
              caseSensitive
                ? "bg-border/70 text-foreground"
                : "text-muted-foreground"
            }`}
          >
            {/* i18n-ignore */}
            Aa
          </button>
          <IconButton
            label={t("workspace_previous_match")}
            onClick={() => step(-1)}
          >
            <ChevronUpIcon className="h-4 w-4" />
          </IconButton>
          <IconButton label={t("workspace_next_match")} onClick={() => step(1)}>
            <ChevronDownIcon className="h-4 w-4" />
          </IconButton>
          <IconButton label={t("workspace_close_find")} onClick={onClose}>
            <XIcon className="h-4 w-4" />
          </IconButton>
        </div>
      </div>
    </div>
  );
}

function IconButton({
  label,
  onClick,
  children,
}: {
  label: string;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      className="text-muted-foreground hover:text-foreground hover:bg-border/70 h-8 w-7 shrink-0 rounded transition-colors"
    >
      <span className="flex items-center justify-center">{children}</span>
    </button>
  );
}

function TextButton({
  label,
  ariaLabel,
  title,
  disabled,
  onClick,
}: {
  label: string;
  ariaLabel?: string;
  title?: string;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-label={ariaLabel ?? label}
      title={title}
      disabled={disabled}
      onClick={onClick}
      className="border-border text-muted-foreground hover:text-foreground hover:border-muted-foreground/40 h-8 shrink-0 rounded-md border px-1.5 text-xs transition-colors disabled:opacity-50 disabled:hover:text-current"
    >
      {label}
    </button>
  );
}
