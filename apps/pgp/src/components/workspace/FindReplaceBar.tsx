import { useEffect, useMemo, useRef, useState } from "react";
import {
  ChevronDownIcon,
  ChevronRightIcon,
  ChevronUpIcon,
  XIcon,
} from "lucide-react";

import {
  cn,
  formatShortcutTitle,
  isMacPlatform,
  type ShortcutSpec,
} from "@amibeingpwned/ui";

import {
  findAll,
  nextMatchIndex,
  prevMatchIndex,
  replaceAll,
  replaceAt,
  type Edit,
} from "~/lib/compose/text-format";
import { t } from "~/lib/i18n";
import { matchesShortcut } from "~/lib/shortcuts";
import { INPUT_CLASS } from "~/lib/utils/styles";

const FIELD_CLASS = "h-7 rounded-md px-2 py-0 text-sm focus:ring-1";

/** Replace-all. Also the workspace's "run" combo, so the bar must swallow
 *  it even with the replace row closed: never Encrypt from a find field. */
const REPLACE_ALL_SHORTCUT: ShortcutSpec = { mod: true, key: "Enter" };

interface FindReplaceBarProps {
  initialQuery: string;
  /** Bumps on a re-press of the open shortcut, to refocus the field. */
  focusNonce: number;
  getText: () => string;
  getSelection: () => { start: number; end: number };
  select: (start: number, end: number) => void;
  apply: (edit: Edit) => void;
  /** Bumps on every text change so the match count stays fresh. */
  textVersion: number;
  /** The owner paints matches: a textarea only shows its selection while
   *  focused, and focus is in this bar. */
  onHighlight: (
    ranges: { start: number; end: number }[],
    current: number,
  ) => void;
  onClose: () => void;
}

/** Find & replace floating over the message box; the current match is
 *  shown by selecting it. Floats so opening it never reflows the text. */
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
  const [showReplace, setShowReplace] = useState(false);
  // -1 for none.
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

  useEffect(() => {
    if (initialQuery) setQuery(initialQuery);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusNonce]);

  // Re-anchor on the first match at or after the caret, not the top.
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
      // The workspace's Escape layers read `defaultPrevented`.
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
      // Column-major (not a row grid) so Tab goes Find -> Replace ->
      // replace buttons without detouring through the find row's icons.
      className="surface-float flex items-start gap-x-0.5 rounded-lg p-0.5 opacity-50 transition-opacity focus-within:opacity-100 hover:opacity-100 motion-reduce:transition-none"
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
        className="text-muted-foreground hover:text-foreground hover:bg-accent flex h-7 w-6 shrink-0 items-center justify-center rounded transition-colors"
      >
        {showReplace ? (
          <ChevronDownIcon className="h-3.5 w-3.5" />
        ) : (
          <ChevronRightIcon className="h-3.5 w-3.5" />
        )}
      </button>
      <div className="flex min-w-0 flex-1 flex-col gap-y-0.5">
        <div className="relative min-w-0">
          <input
            ref={findRef}
            type="text"
            aria-label={t("workspace_find_label")}
            placeholder={t("workspace_find_label")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onFindKey}
            className={cn(INPUT_CLASS, FIELD_CLASS, "w-full pr-14")}
          />
          <span
            className="text-muted-foreground pointer-events-none absolute inset-y-0 right-2 flex items-center text-xs tabular-nums"
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
            className={cn(INPUT_CLASS, FIELD_CLASS, "min-w-0")}
          />
        )}
      </div>
      {/* flex-col-reverse: replace buttons first in DOM for Tab order. */}
      <div className="flex w-30 shrink-0 flex-col-reverse gap-y-0.5">
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
            className={`hover:text-foreground h-7 w-7 shrink-0 rounded font-mono text-xs transition-colors ${
              caseSensitive
                ? "bg-on text-on-foreground"
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
            <ChevronUpIcon className="h-3.5 w-3.5" />
          </IconButton>
          <IconButton label={t("workspace_next_match")} onClick={() => step(1)}>
            <ChevronDownIcon className="h-3.5 w-3.5" />
          </IconButton>
          <IconButton label={t("workspace_close_find")} onClick={onClose}>
            <XIcon className="h-3.5 w-3.5" />
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
      className="text-muted-foreground hover:text-foreground hover:bg-accent h-7 w-7 shrink-0 rounded transition-colors"
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
      className="text-muted-foreground hover:text-foreground hover:bg-accent h-7 shrink-0 rounded px-1.5 text-sm transition-colors disabled:opacity-50 disabled:hover:bg-transparent disabled:hover:text-current"
    >
      {label}
    </button>
  );
}
