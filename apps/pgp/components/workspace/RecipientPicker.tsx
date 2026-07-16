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
import { formatKeyDisplayName } from "../../lib/utils/key-naming";

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
}

function getKeyDisplay(key: AnyKey): { name: string; detail: string } {
  const userId = key.userIds[0];
  if (!userId) return { name: key.keyId.slice(-8).toUpperCase(), detail: "" };
  return formatKeyDisplayName(userId);
}

/**
 * Multi-recipient combobox for encrypt mode: selected recipients render
 * as removable chips ahead of an inline search input (one box, one
 * affordance -- click anywhere and type), the dropdown offers the
 * remaining keys with recently-used ones first, and digits 1-9
 * quick-pick the nth visible option while the input is empty.
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
}: RecipientPickerProps) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  // cmdk's highlighted option, controlled so it can reset between opens
  // (otherwise cmdk keeps pointing at the just-picked, now-absent item
  // and Enter silently does nothing on reopen).
  const [highlighted, setHighlighted] = useState("");
  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  // Focus opens the dropdown -- except when WE move focus back into the
  // input after a close (e.g. after a click-pick), which must not
  // immediately reopen it.
  const suppressOpenOnFocus = useRef(false);
  const inputId = useId();
  const listId = useId();

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
              <button onClick={emptyAction} className="text-primary underline">
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
  // Render order, flattened -- what the digit shortcuts index into.
  const visibleKeys = [...recent, ...restContacts, ...restMyKeys];

  const closeDropdown = () => {
    setOpen(false);
    // A stale filter surviving into the next open is confusing; start
    // each open with the full list.
    setSearch("");
    setHighlighted("");
  };

  /** Return focus to the inline input without reopening the dropdown. */
  const refocusInput = () => {
    const input = inputRef.current;
    if (!input || document.activeElement === input) return;
    suppressOpenOnFocus.current = true;
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
    // Escape closes the dropdown ONLY -- stop it here so the surrounding
    // view/slide-over (document-level listener) doesn't also close.
    // While the dropdown is open Radix's document capture listener
    // usually swallows Escape first (see onEscapeKeyDown below); this
    // branch is the fallback. With nothing open, Escape falls through
    // to the slide-over as before.
    if (e.key === "Escape") {
      if (open || search !== "") {
        e.preventDefault();
        e.stopPropagation();
        closeDropdown();
      }
      return;
    }
    // Backspace in the empty input pops the last chip, like Linear.
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
      if (index < visibleKeys.length) {
        e.preventDefault();
        addRecipient(visibleKeys[index].keyId, { keepOpen: true });
      }
    }
  };

  /** 1-based digit shortcut for `key` in the visible list, if it has one. */
  const digitFor = (key: AnyKey): number | null => {
    if (search !== "") return null;
    const index = visibleKeys.indexOf(key);
    return index >= 0 && index < 9 ? index + 1 : null;
  };

  const renderOption = (key: AnyKey) => {
    const { name, detail } = getKeyDisplay(key);
    const digit = digitFor(key);
    // Own keys carry a "You" badge so they read at a glance in mixed
    // groups (Recent, search results) where the group heading can't help.
    const isOwn = !contactIds.has(key.keyId);
    return (
      <CommandItem
        key={key.keyId}
        value={
          detail ? `${name} ${detail} ${key.keyId}` : `${name} ${key.keyId}`
        }
        onSelect={() => addRecipient(key.keyId)}
        className="gap-2"
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
          </p>
          {detail && (
            <p className="text-muted-foreground truncate text-xs">{detail}</p>
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
                input (Linear-style multiselect combobox): clicking
                anywhere in the box focuses the input, and typing
                filters the dropdown directly -- no second search field. */}
            <div
              ref={containerRef}
              onClick={() => {
                setOpen(true);
                inputRef.current?.focus();
              }}
              className="border-input focus-within:ring-ring flex min-h-9 w-full cursor-text flex-wrap items-center gap-1 rounded-md border bg-transparent px-2 py-1.5 text-sm focus-within:ring-1"
            >
              {selectedKeys.map((key) => {
                const { name, detail } = getKeyDisplay(key);
                return (
                  <span
                    key={key.keyId}
                    title={detail ? `${name} - ${detail}` : name}
                    // max-w-full (not a fixed cap): a chip sizes to its
                    // content and only truncates when the row genuinely
                    // can't fit it. With several chips the flex-wrap row
                    // wraps first, so truncation stays a last resort.
                    className="bg-secondary text-secondary-foreground inline-flex max-w-full items-center gap-1 rounded-md border px-2 py-0.5 text-xs"
                  >
                    <span className="min-w-0 truncate">{name}</span>
                    <button
                      type="button"
                      aria-label={`Remove ${name}`}
                      className="text-muted-foreground hover:text-foreground -mr-0.5 shrink-0 rounded-sm"
                      onClick={(e) => {
                        // Removing a chip must not toggle the dropdown.
                        e.stopPropagation();
                        removeRecipient(key.keyId);
                      }}
                    >
                      <XIcon className="h-3 w-3" />
                    </button>
                  </span>
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
                  if (suppressOpenOnFocus.current) {
                    suppressOpenOnFocus.current = false;
                    return;
                  }
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
