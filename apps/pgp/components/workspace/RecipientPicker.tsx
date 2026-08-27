import { useId, useRef, useState } from "react";
import { ChevronsUpDownIcon, XIcon } from "lucide-react";

import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@amibeingpwned/ui/command";
import {
  Popover,
  PopoverAnchor,
  PopoverContent,
} from "@amibeingpwned/ui/popover";

import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import {
  matchesRecipientSearch,
  orderRecipients,
} from "../../lib/recipient-ordering";
import {
  activeRecipients,
  contactRecipients,
} from "../../lib/storage/contacts";
import { isSshRecord } from "../../lib/storage/key-kind";
import {
  displayUserId,
  formatKeyDisplayName,
} from "../../lib/utils/key-naming";
import {
  pickableKeys,
  recipientBlockReason,
  selectionEngine,
} from "./recipient-engine";

type AnyKey = ProtectedKeyBlob | PublicContactKey;

interface RecipientPickerProps {
  label: string;
  contacts: PublicContactKey[];
  myKeys: ProtectedKeyBlob[];
  /** Selected recipient key ids, in selection order (chip order). */
  selectedKeyIds: string[];
  /** Recently used recipient fingerprints, most recent first. */
  recentKeyIds: string[];
  onChange: (keyIds: string[]) => void;
  emptyText?: string;
  emptyAction?: () => void;
  emptyActionLabel?: string;
  /** A message password is set. Rules out SSH recipients entirely --
   *  age has no password mode -- so they dim with their own reason. */
  passwordArmed?: boolean;
}

function getKeyDisplay(key: AnyKey): { name: string; detail: string } {
  // The local alias when there is one -- through the shared accessor, so
  // a key renamed in the Keys tab is renamed here too.
  const userId = displayUserId(key);
  if (!userId) return { name: key.keyId.slice(-8).toUpperCase(), detail: "" };
  return formatKeyDisplayName(userId);
}

/**
 * Multi-recipient combobox for encrypt mode: selected recipients render
 * as removable chips ahead of an inline search input (one box, one
 * affordance -- click anywhere and type), the dropdown offers the
 * remaining keys with recently-used ones first, and digits 1-9
 * quick-pick the nth visible option while the input is empty.
 *
 * The dropdown opens on a deliberate gesture -- a click in the box, the
 * chevron, typing, Arrow/Enter, or TABBING INTO IT. Focus on its own is
 * still not intent: the box also gets focused when the panel regains
 * focus, by re-renders after the mod+Enter Run shortcut, and by
 * programmatic focus, and popping the list open in those cases reads as
 * a dialog appearing out of nowhere. So the focus handler opens only
 * when a Tab keydown immediately preceded it -- see `arrivedByTab`.
 */
export function RecipientPicker({
  label,
  contacts,
  myKeys,
  selectedKeyIds,
  recentKeyIds,
  onChange,
  emptyText = "No keys available",
  emptyAction,
  emptyActionLabel,
  passwordArmed = false,
}: RecipientPickerProps) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  // Whether the focus about to arrive came from a TAB. Focus alone is
  // not intent (see this component's doc comment); a Tab press is. The
  // flag is set on the keydown that will move focus and cleared the
  // moment it is used, so a later programmatic focus cannot inherit it.
  const arrivedByTab = useRef(false);
  // cmdk's highlighted option, controlled so it can reset between opens
  // (otherwise cmdk keeps pointing at the just-picked, now-absent item
  // and Enter silently does nothing on reopen).
  const [highlighted, setHighlighted] = useState("");
  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const inputId = useId();
  const listId = useId();

  // Capture phase, on the keydown BEFORE the browser moves focus, so the
  // focus handler below can tell a Tab arrival from every other way this
  // box gets focused. Any other key (or a pointer press) clears it --
  // otherwise a Tab somewhere else in the panel would still be "armed"
  // when a re-render later parked focus here.
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      arrivedByTab.current = e.key === "Tab";
    };
    const clear = () => {
      arrivedByTab.current = false;
    };
    document.addEventListener("keydown", onKeyDown, true);
    document.addEventListener("pointerdown", clear, true);
    return () => {
      document.removeEventListener("keydown", onKeyDown, true);
      document.removeEventListener("pointerdown", clear, true);
    };
  }, []);

  const allKeys: AnyKey[] = [...contacts, ...myKeys];

  if (allKeys.length === 0) {
    return (
      <div>
        <span className="text-muted-foreground text-xs font-medium">
          {label}
        </span>
        <p className="text-muted-foreground text-xs">
          {emptyText}
          {emptyAction && (
            <>
              {" "}
              <button
                type="button"
                // Don't pass emptyAction directly: the MouseEvent would leak
                // into callers typed (importPrefill?: string) and get treated
                // as a truthy prefill.
                onClick={() => emptyAction()}
                className="text-primary underline"
              >
                {emptyActionLabel ?? "Set up"}
              </button>
            </>
          )}
        </p>
      </div>
    );
  }

  const selectedKeys = selectedKeyIds
    .map((id) => allKeys.find((k) => k.keyId === id))
    .filter((k): k is AnyKey => k !== undefined);

  // Already-selected recipients don't reappear in the dropdown. The
  // inline input is the single search field, so filtering happens here
  // (Command runs with shouldFilter={false}).
  const selectedSet = new Set(selectedKeyIds);
  const available = allKeys.filter(
    (k) => !selectedSet.has(k.keyId) && matchesRecipientSearch(k, search),
  );
  const contactIds = new Set(contacts.map((c) => c.keyId));
  // Own keys always sort BELOW contacts: they never join the Recent group
  // (you rarely encrypt to yourself explicitly), so recency ordering only
  // applies to actual recipients.
  const availableContacts = available.filter((k) => contactIds.has(k.keyId));
  const availableOwn = available.filter((k) => !contactIds.has(k.keyId));
  const { recent, rest: restContacts } = orderRecipients(
    availableContacts,
    recentKeyIds,
  );
  const { rest: restMyKeys } = orderRecipients(availableOwn, []);
  // Render order, flattened.
  const visibleKeys = [...recent, ...restContacts, ...restMyKeys];
  // The engine the selection has committed to (null while nothing is
  // selected), and the subset of the rendered list a keyboard gesture may
  // land on. The two lists are deliberately separate: options of the
  // other engine still RENDER -- dimmed, with the reason -- but must be
  // invisible to the digit shortcuts and to Enter, or a disabled row
  // sitting third would silently eat the `3` keystroke.
  const engine = selectionEngine(selectedKeys);
  const pickable = pickableKeys(visibleKeys, engine, passwordArmed);

  const closeDropdown = () => {
    setOpen(false);
    // A stale filter surviving into the next open is confusing; start
    // each open with the full list.
    setSearch("");
    setHighlighted("");
  };

  /** Return focus to the inline input. Focus alone never opens the
   *  dropdown, so this is always safe. */
  const refocusInput = () => {
    const input = inputRef.current;
    if (!input || document.activeElement === input) return;
    input.focus();
  };

  // Click/Enter picks close the popover (the deliberate single pick);
  // digit quick-picks keep it open for rapid multi-add.
  const addRecipient = (keyId: string, opts?: { keepOpen?: boolean }) => {
    onChange([...selectedKeyIds, keyId]);
    setSearch("");
    if (!opts?.keepOpen) {
      closeDropdown();
      // A pointer pick moved focus to the list; hand it back so the
      // user can keep typing.
      refocusInput();
    }
  };
  const removeRecipient = (keyId: string) => {
    onChange(selectedKeyIds.filter((id) => id !== keyId));
  };

  const handleInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    // Escape peels one layer per press for keyboard users: #1 closes
    // the list (query kept, so reopening resumes the filter), #2 clears
    // the typed query, #3 falls through to the slide-over. stopPropagation
    // so the slide-over's document-level listener doesn't also close.
    // While the dropdown is open Radix's document capture listener
    // usually swallows Escape first (see onEscapeKeyDown below); this
    // branch is the fallback.
    if (e.key === "Escape") {
      if (open) {
        e.preventDefault();
        e.stopPropagation();
        setOpen(false);
        setHighlighted("");
        return;
      }
      if (search !== "") {
        e.preventDefault();
        e.stopPropagation();
        setSearch("");
      }
      return;
    }
    // Enter with the list closed opens it -- the box should always
    // "show the thing" from the keyboard. When open, Enter bubbles to
    // the Command root and picks the highlighted option -- UNLESS the
    // filter has moved on and the highlight points at nothing visible
    // (cmdk would silently no-op); then Enter picks the TOP match, so
    // "type until one result, Enter" always works.
    if (e.key === "Enter") {
      // mod+Enter is the global Run shortcut, never a picker gesture:
      // preventDefault so cmdk skips its own Enter pick (it bails on
      // defaultPrevented), close the list, and let the event bubble on
      // to the window-level shortcut listener that runs the action.
      if (e.metaKey || e.ctrlKey || e.altKey) {
        e.preventDefault();
        if (open) closeDropdown();
        return;
      }
      if (!open) {
        e.preventDefault();
        setOpen(true);
        return;
      }
      const highlightVisible = pickable.some(
        (k) => itemValue(k) === highlighted,
      );
      if (!highlightVisible && pickable.length > 0) {
        e.preventDefault();
        e.stopPropagation();
        addRecipient(pickable[0].keyId);
      }
      return;
    }
    // Backspace in the empty input pops the last chip.
    if (e.key === "Backspace" && search === "" && selectedKeyIds.length > 0) {
      e.preventDefault();
      onChange(selectedKeyIds.slice(0, -1));
      return;
    }
    // Arrow keys open the dropdown; once open they bubble to the
    // Command root, which moves the cmdk highlight through the list.
    if ((e.key === "ArrowDown" || e.key === "ArrowUp") && !open) {
      e.preventDefault();
      setOpen(true);
      return;
    }
    // Digits quick-pick the nth visible option, but only while the input
    // is EMPTY -- typing numbers into a query must never trigger picks.
    // Plain digits only: mod+1..4 belong to the global mode shortcuts
    // (action registry), which fire even while an input has focus.
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (open && search === "" && /^[1-9]$/.test(e.key)) {
      const index = Number(e.key) - 1;
      if (index < pickable.length) {
        e.preventDefault();
        addRecipient(pickable[index].keyId, { keepOpen: true });
      }
    }
  };

  /** The cmdk item value for a key -- must match renderOption's value. */
  const itemValue = (key: AnyKey): string => {
    const { name, detail } = getKeyDisplay(key);
    return detail ? `${name} ${detail} ${key.keyId}` : `${name} ${key.keyId}`;
  };

  /** 1-based digit shortcut for `key`, if it has one. Numbered off the
   *  PICKABLE list so the digits shown match the digits that work -- a
   *  blocked option shows no number at all. */
  const digitFor = (key: AnyKey): number | null => {
    if (search !== "") return null;
    const index = pickable.indexOf(key);
    return index >= 0 && index < 9 ? index + 1 : null;
  };

  // The first blocked option in render order carries the reason as a
  // visible sub-line. Only the first: repeating one sentence down a whole
  // group turns the explanation into wallpaper, and hover-only (a
  // `title`) would leave it undiscoverable on touch and to the keyboard.
  const firstBlockedId = visibleKeys.find(
    (k) => recipientBlockReason(k, engine, passwordArmed) !== null,
  )?.keyId;

  const renderOption = (key: AnyKey) => {
    const { name, detail } = getKeyDisplay(key);
    const digit = digitFor(key);
    // Own keys carry a "You" badge so they read at a glance in mixed
    // groups (Recent, search results) where the group heading can't help.
    // An "SSH" badge does the same job for the engine, which otherwise
    // shows up only once the mixing is already refused.
    const isOwn = !contactIds.has(key.keyId);
    const isSsh = isSshRecord(key);
    // A contact can hold several keys (a fetched person's laptop,
    // desktop, phone), and picking it encrypts to all of them. Nothing
    // about the selection changes -- one contact, one chip, one keyId --
    // but the resulting file has a stanza per key, so say so here rather
    // than letting the size of the output be the first hint.
    const keyCount =
      "armoredPublicKey" in key ? contactRecipients(key).length : 1;
    // ...minus any the user turned off in the contact's key details.
    // The sub-line exists so the number of stanzas in the output is not
    // a surprise, which only works if it counts the keys that will
    // actually be there.
    const activeKeyCount =
      "armoredPublicKey" in key ? activeRecipients(key).length : 1;
    const blockReason = recipientBlockReason(key, engine, passwordArmed);
    const blocked = blockReason !== null;
    return (
      <CommandItem
        key={key.keyId}
        value={itemValue(key)}
        disabled={blocked}
        aria-disabled={blocked || undefined}
        title={blockReason ?? undefined}
        onSelect={() => {
          if (blocked) return;
          addRecipient(key.keyId);
        }}
        className={`gap-2 ${blocked ? "opacity-50" : ""}`}
        aria-keyshortcuts={digit !== null ? String(digit) : undefined}
      >
        <div className="min-w-0 flex-1">
          <p className="flex items-center gap-1.5 truncate text-sm">
            <span className="truncate">{name}</span>
            {isOwn && (
              <span className="bg-secondary text-muted-foreground shrink-0 rounded border px-1 text-[10px] leading-4">
                You
              </span>
            )}
            {isSsh && (
              <span className="bg-secondary text-muted-foreground shrink-0 rounded border px-1 text-[10px] leading-4">
                SSH
              </span>
            )}
          </p>
          {(detail || keyCount > 1) && (
            <p className="text-muted-foreground truncate text-xs">
              {[
                detail,
                keyCount > 1
                  ? activeKeyCount < keyCount
                    ? `${activeKeyCount} of ${keyCount} keys`
                    : `${keyCount} keys`
                  : "",
              ]
                .filter(Boolean)
                .join(" · ")}
            </p>
          )}
          {/* Spelled out once, on the first dimmed row: a `title`
              tooltip is invisible to touch and to the keyboard, and this
              is the only place the refusal gets explained. */}
          {key.keyId === firstBlockedId && blockReason !== null && (
            <p className="text-muted-foreground mt-0.5 text-xs">
              {blockReason}
            </p>
          )}
        </div>
        {digit !== null && <CommandShortcut>{digit}</CommandShortcut>}
      </CommandItem>
    );
  };

  return (
    <div>
      <label
        htmlFor={inputId}
        className="text-muted-foreground mb-1 block text-xs font-medium"
      >
        {label}
      </label>
      {/* Command wraps BOTH the trigger box and the (portaled) list so
          the inline input drives cmdk: its keystrokes bubble to this
          root, which handles ArrowUp/Down/Enter over the list.
          Filtering is manual (shouldFilter={false}) via
          matchesRecipientSearch above. */}
      <Command
        shouldFilter={false}
        value={highlighted}
        onValueChange={setHighlighted}
        className="overflow-visible bg-transparent"
      >
        <Popover
          open={open}
          onOpenChange={(next) => (next ? setOpen(true) : closeDropdown())}
        >
          <PopoverAnchor asChild>
            {/* Chips live INSIDE the selection box ahead of a real text
                input (multiselect combobox): clicking
                anywhere in the box focuses the input, and typing
                filters the dropdown directly -- no second search field. */}
            <div
              ref={containerRef}
              onClick={() => {
                setOpen(true);
                inputRef.current?.focus();
              }}
              onKeyDown={(e) => {
                // Typing while focus sits elsewhere in the box (a chip,
                // the clear-all/chevron buttons) belongs to the search
                // input: refocus it and let the browser insert the
                // character there. Space stays with the focused control
                // (it activates chips/buttons), and modified keys stay
                // shortcuts.
                if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey)
                  return;
                if (e.key.length !== 1 || e.key === " ") return;
                const input = inputRef.current;
                if (!input || e.target === input) return;
                // The browser then inserts the character into the input,
                // whose onChange opens the dropdown with the new filter.
                input.focus();
              }}
              className="border-input focus-within:ring-ring flex min-h-9 w-full cursor-text flex-wrap items-center gap-1 rounded-md border bg-transparent px-2 py-1.5 text-sm focus-within:ring-1"
            >
              {selectedKeys.map((key) => {
                const { name, detail } = getKeyDisplay(key);
                return (
                  // The WHOLE chip is the remove button (the bare x was
                  // too small a target); the x icon stays as the visual
                  // affordance. Legal because the trigger box is a div,
                  // not a button -- no nested-button problem.
                  <button
                    key={key.keyId}
                    type="button"
                    aria-label={`Remove ${name}`}
                    title={
                      detail ? `Remove ${name} - ${detail}` : `Remove ${name}`
                    }
                    // max-w-full (not a fixed cap): a chip sizes to its
                    // content and only truncates when the row genuinely
                    // can't fit it. With several chips the flex-wrap row
                    // wraps first, so truncation stays a last resort.
                    // Hover tints destructive (the HistoryPage-delete
                    // idiom) so the click reads as removal, not selection.
                    className="bg-secondary text-secondary-foreground hover:border-destructive/40 hover:bg-destructive/10 hover:text-destructive inline-flex max-w-full cursor-pointer items-center gap-1 rounded-md border px-2 py-0.5 text-xs transition-colors"
                    onClick={(e) => {
                      // Removing a chip must not toggle the dropdown
                      // (the container's own click handler opens it).
                      e.stopPropagation();
                      removeRecipient(key.keyId);
                      // The chip unmounts with focus on it; hand focus
                      // back to the input (suppressed, so it doesn't
                      // reopen the dropdown) so the user can keep typing.
                      refocusInput();
                    }}
                    onKeyDown={(e) => {
                      // A Tab-focused chip should also delete on
                      // Backspace/Delete, not only Enter/Space -- that's
                      // what a keyboard user reaches for on a chip.
                      if (e.key === "Backspace" || e.key === "Delete") {
                        e.preventDefault();
                        e.stopPropagation();
                        removeRecipient(key.keyId);
                        refocusInput();
                      }
                    }}
                  >
                    <span className="min-w-0 truncate">{name}</span>
                    {isSshRecord(key) && (
                      // `mx-0.5` on top of the chip's `gap-1`: the badge
                      // is a bordered box sitting between two pieces of
                      // bare text, so the 4px gap that reads fine either
                      // side of a glyph reads cramped either side of a
                      // border. Nudged here rather than on the chip's
                      // gap so chips WITHOUT the badge keep their
                      // spacing.
                      <span className="text-muted-foreground mx-0.5 shrink-0 rounded border px-1 text-[10px] leading-4">
                        SSH
                      </span>
                    )}
                    <XIcon className="-mr-0.5 h-3 w-3 shrink-0 opacity-60" />
                  </button>
                );
              })}
              <input
                ref={inputRef}
                id={inputId}
                type="text"
                role="combobox"
                aria-expanded={open}
                aria-controls={open ? listId : undefined}
                aria-autocomplete="list"
                autoComplete="off"
                spellCheck={false}
                placeholder={
                  selectedKeys.length > 0 ? undefined : "Add recipients..."
                }
                title="Backspace removes the last recipient"
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  if (!open) setOpen(true);
                }}
                onFocus={() => {
                  // Tab arrivals open the list; every other route into
                  // this box does not. The three cases the component's
                  // doc comment names -- the panel regaining focus, a
                  // re-render after the mod+Enter Run shortcut, and a
                  // programmatic focus -- all reach here with no Tab
                  // keydown behind them and are left alone.
                  if (!arrivedByTab.current) return;
                  arrivedByTab.current = false;
                  setOpen(true);
                }}
                onKeyDown={handleInputKeyDown}
                className="placeholder:text-muted-foreground min-w-16 flex-1 bg-transparent outline-none"
              />
              {selectedKeys.length > 1 && (
                <button
                  type="button"
                  aria-label="Clear all recipients"
                  title="Clear all recipients"
                  className="text-muted-foreground hover:text-foreground shrink-0 rounded-sm"
                  onClick={(e) => {
                    // Clearing must not toggle the dropdown.
                    e.stopPropagation();
                    onChange([]);
                  }}
                >
                  <XIcon className="h-4 w-4" />
                </button>
              )}
              <button
                type="button"
                // Not a tab stop: the input is the control, the chevron
                // is a pointer convenience.
                tabIndex={-1}
                aria-label="Toggle recipient list"
                className="ml-1 shrink-0 rounded-sm"
                onClick={(e) => {
                  e.stopPropagation();
                  if (open) {
                    closeDropdown();
                  } else {
                    setOpen(true);
                    inputRef.current?.focus();
                  }
                }}
              >
                <ChevronsUpDownIcon className="h-4 w-4 opacity-50" />
              </button>
            </div>
          </PopoverAnchor>
          {/* Pin the list ABOVE the trigger and disable collision flipping
              so it doesn't jump between top/bottom as the result count
              changes while searching. */}
          <PopoverContent
            side="top"
            avoidCollisions={false}
            className="w-(--radix-popover-trigger-width) p-0"
            // Focus stays in the inline input; the popover is display-only.
            onOpenAutoFocus={(e) => e.preventDefault()}
            // Focus is handed off explicitly on close (refocusInput after
            // a pick; unchanged after Escape; wherever the user clicked
            // after an outside dismiss) -- keep Radix out of it.
            onCloseAutoFocus={(e) => e.preventDefault()}
            // The input lives in the ANCHOR, not the content: without
            // this guard, clicks and focus inside the trigger box count
            // as "outside" and dismiss the dropdown mid-interaction.
            onInteractOutside={(e) => {
              if (
                containerRef.current &&
                e.target instanceof Node &&
                containerRef.current.contains(e.target)
              ) {
                e.preventDefault();
              }
            }}
            // Radix's own Escape handling runs on a document capture
            // listener; stop the event there too so it can't bubble on to
            // the slide-over stack's document listener.
            onEscapeKeyDown={(e) => e.stopPropagation()}
          >
            {/* Fixed height (not just max-h) so the list stays a constant
                size and doesn't grow/shrink as search filters the results. */}
            <CommandList id={listId} className="h-[300px]">
              <CommandEmpty>No matches</CommandEmpty>
              {recent.length > 0 && (
                <>
                  <CommandGroup heading="Recent">
                    {recent.map(renderOption)}
                  </CommandGroup>
                  {(restContacts.length > 0 || restMyKeys.length > 0) && (
                    <CommandSeparator />
                  )}
                </>
              )}
              {restContacts.length > 0 && (
                <CommandGroup heading="Contacts">
                  {restContacts.map(renderOption)}
                </CommandGroup>
              )}
              {restContacts.length > 0 && restMyKeys.length > 0 && (
                <CommandSeparator />
              )}
              {restMyKeys.length > 0 && (
                <CommandGroup heading="My Keys">
                  {restMyKeys.map(renderOption)}
                </CommandGroup>
              )}
            </CommandList>
          </PopoverContent>
        </Popover>
      </Command>
    </div>
  );
}
