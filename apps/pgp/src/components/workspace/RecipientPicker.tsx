import { useId, useMemo, useRef, useState } from "react";
import { ChevronsUpDownIcon, InfoIcon, XIcon } from "lucide-react";

import {
  cn,
  Command,
  CommandEmpty,
  CommandGroup,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
  Popover,
  PopoverAnchor,
  PopoverContent,
} from "@amibeingpwned/ui";

import { keyDetailsTarget } from "~/components/keys/KeyDetailsButton";
import { KeyDetailsPage } from "~/components/keys/KeyDetailsPage";
import { KeyAvatar } from "~/components/shared/KeyAvatar";
import { MarkedText } from "~/components/shared/MarkedText";
import { t, tn } from "~/lib/i18n";
import {
  contactClashes,
  displayKeyId,
  noteKeyId,
} from "~/lib/identity/binding";
import { clashPillLabel, clashSentence } from "~/lib/identity/clash-copy";
import {
  matchesRecipientSearch,
  orderRecipients,
} from "~/lib/recipient-ordering";
import {
  activeRecipients,
  contactRecipients,
  type PublicContactKey,
} from "~/lib/storage/contacts";
import { isSshRecord } from "~/lib/storage/key-kind";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import { displayUserId, formatKeyDisplayName } from "~/lib/utils/key-naming";
import {
  pickableKeys,
  recipientBlockReason,
  selectionEngine,
  splitRecipientSections,
} from "./recipient-engine";

type AnyKey = ProtectedKeyBlob | PublicContactKey;

interface RecipientPickerProps {
  label: string;
  contacts: PublicContactKey[];
  myKeys: ProtectedKeyBlob[];
  selectedKeyIds: string[];
  /** Most recent first. */
  recentKeyIds: string[];
  onChange: (keyIds: string[]) => void;
  emptyText?: string;
  emptyAction?: () => void;
  emptyActionLabel?: string;
  /** Rules out SSH recipients (age has no password mode). */
  passwordArmed?: boolean;
  /** Escape with nothing left to close or clear. A callback because
   *  cmdk/Radix consume Escape before any document listener sees it. */
  onEscapeExhausted?: () => void;
  /** The card's "To" row: no own well, list drops down. */
  inline?: boolean;
}

function getKeyDisplay(key: AnyKey): { name: string; detail: string } {
  const userId = displayUserId(key);
  if (!userId) return { name: key.keyId.slice(-8).toUpperCase(), detail: "" };
  return formatKeyDisplayName(userId);
}

/**
 * Multi-recipient chip combobox for encrypt mode. The dropdown opens only
 * on a deliberate gesture; plain focus (panel refocus, post-Run re-render,
 * programmatic) is not intent, so focus opens it only after a Tab keydown
 * (`arrivedByTab`).
 */
export function RecipientPicker({
  label,
  contacts,
  myKeys,
  selectedKeyIds,
  recentKeyIds,
  onChange,
  emptyText,
  emptyAction,
  emptyActionLabel,
  passwordArmed = false,
  onEscapeExhausted,
  inline = false,
}: RecipientPickerProps) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  // Cleared the moment it is used, so a later programmatic focus cannot
  // inherit it.
  const arrivedByTab = useRef(false);
  // Controlled so it resets between opens; otherwise cmdk points at the
  // just-picked, now-absent item and Enter silently no-ops.
  const [highlighted, setHighlighted] = useState("");
  const [detailsKey, setDetailsKey] = useState<AnyKey | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const inputId = useId();
  const listId = useId();

  // Escape's LAST layer, in capture phase: Radix stops Escape on its own
  // document capture listener, so no bubble handler ever sees it. Must be
  // registered ONCE at mount (state via ref) to stay ahead of Radix's
  // listener; capture listeners fire in registration order.
  const escapeState = useRef({ open, search, onEscapeExhausted });
  useEffect(() => {
    escapeState.current = { open, search, onEscapeExhausted };
  });

  useEffect(() => {
    const onEscape = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || e.defaultPrevented) return;
      const {
        open: isOpen,
        search: query,
        onEscapeExhausted: exhausted,
      } = escapeState.current;
      if (!exhausted) return;
      if (isOpen || query !== "") return;
      const active = document.activeElement;
      if (!(active instanceof Node) || !containerRef.current?.contains(active))
        return;
      exhausted();
    };
    document.addEventListener("keydown", onEscape, true);
    return () => document.removeEventListener("keydown", onEscape, true);
  }, []);

  // Capture phase, before the browser moves focus; any other key or a
  // pointer press disarms it.
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

  // Two contacts claiming one name are flagged so the pick is made on the
  // key id (SSH comments are whatever the file said).
  const clashes = useMemo(
    () => contactClashes(contacts, myKeys),
    [contacts, myKeys],
  );

  const allKeys: AnyKey[] = [...contacts, ...myKeys];

  if (allKeys.length === 0) {
    return (
      <div className={inline ? "flex items-baseline gap-3 px-3 py-2.5" : ""}>
        <span className="text-muted-foreground shrink-0 text-xs font-medium">
          {label}
        </span>
        <p className="text-muted-foreground text-xs">
          {emptyText ?? t("actions_no_keys_available")}
          {emptyAction && (
            <>
              {" "}
              <button
                type="button"
                // Not passed directly: the MouseEvent would become a truthy
                // `importPrefill`.
                onClick={() => emptyAction()}
                className="text-primary underline"
              >
                {emptyActionLabel ?? t("actions_set_up")}
              </button>
            </>
          )}
        </p>
      </div>
    );
  }

  // Own keys first: an id that is yours means your key, as in
  // `resolveSelectedRecipients`.
  const selectedKeys = selectedKeyIds
    .map(
      (id) =>
        myKeys.find((k) => k.keyId === id) ??
        contacts.find((k) => k.keyId === id),
    )
    .filter((k): k is AnyKey => k !== undefined);

  // Filtering is manual here (Command has shouldFilter={false}).
  const selectedSet = new Set(selectedKeyIds);
  const available = allKeys.filter(
    (k) => !selectedSet.has(k.keyId) && matchesRecipientSearch(k, search),
  );
  // By record, not fingerprint: one key can be both yours and a contact's.
  const contactRecords = new Set<AnyKey>(contacts);
  const { contacts: availableContacts, own: availableOwn } =
    splitRecipientSections<PublicContactKey, ProtectedKeyBlob>(
      available,
      contacts,
      new Set(myKeys.map((k) => k.keyId)),
    );
  const { recent, rest: restContacts } = orderRecipients(
    availableContacts,
    recentKeyIds,
  );
  const { rest: restMyKeys } = orderRecipients(availableOwn, []);
  const visibleKeys = [...recent, ...restContacts, ...restMyKeys];
  // Keyboard picks index `pickable`, never `visibleKeys` (see pickableKeys).
  const engine = selectionEngine(selectedKeys);
  const pickable = pickableKeys(visibleKeys, engine, passwordArmed);

  const closeDropdown = () => {
    setOpen(false);
    setSearch("");
    setHighlighted("");
  };

  /** Safe: focus alone never opens the dropdown. */
  const refocusInput = () => {
    const input = inputRef.current;
    if (!input || document.activeElement === input) return;
    input.focus();
  };

  // Digit quick-picks keep the list open for rapid multi-add.
  const addRecipient = (keyId: string, opts?: { keepOpen?: boolean }) => {
    onChange([...selectedKeyIds, keyId]);
    setSearch("");
    if (!opts?.keepOpen) {
      closeDropdown();
      refocusInput();
    }
  };
  const removeRecipient = (keyId: string) => {
    onChange(selectedKeyIds.filter((id) => id !== keyId));
  };

  const handleInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    // Escape peels: close list, clear query, hand back to the workspace.
    // Only the query clear really lands here; Radix and the capture-phase
    // effect above own the other two.
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
    // Open: Enter picks the highlight, or the TOP match when the highlight
    // is stale (cmdk would silently no-op).
    if (e.key === "Enter") {
      // mod+Enter is Run: preventDefault so cmdk skips its pick, but let
      // it bubble to the window shortcut listener.
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
    if (e.key === "Backspace" && search === "" && selectedKeyIds.length > 0) {
      e.preventDefault();
      onChange(selectedKeyIds.slice(0, -1));
      return;
    }
    if ((e.key === "ArrowDown" || e.key === "ArrowUp") && !open) {
      e.preventDefault();
      setOpen(true);
      return;
    }
    // Digits pick only while the query is EMPTY, and only unmodified
    // (mod+1..4 are the global mode shortcuts).
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

  /** Numbered off `pickable`, so shown digits are the ones that work. */
  const digitFor = (key: AnyKey): number | null => {
    if (search !== "") return null;
    const index = pickable.indexOf(key);
    return index >= 0 && index < 9 ? index + 1 : null;
  };

  // Only the first blocked row spells out its reason (a `title` alone is
  // invisible to touch and keyboard).
  const firstBlockedId = visibleKeys.find(
    (k) => recipientBlockReason(k, engine, passwordArmed) !== null,
  )?.keyId;

  const renderOption = (key: AnyKey) => {
    const { name, detail } = getKeyDisplay(key);
    const digit = digitFor(key);
    const isOwn = !contactRecords.has(key);
    const isSsh = isSshRecord(key);
    // Picking a contact encrypts to ALL its active keys; say so up front.
    const keyCount =
      "armoredPublicKey" in key ? contactRecipients(key).length : 1;
    const activeKeyCount =
      "armoredPublicKey" in key ? activeRecipients(key).length : 1;
    const blockReason = recipientBlockReason(key, engine, passwordArmed);
    const blocked = blockReason !== null;
    const verified = !isOwn && "verified" in key && key.verified === true;
    const clash = isOwn ? undefined : clashes.get(key.keyId);
    // Always shown: the id tells two keys with one name apart.
    const shortKeyId = isSsh ? noteKeyId(key.keyId) : displayKeyId(key.keyId);
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
        className={`gap-2.5 ${blocked ? "opacity-50" : ""}`}
        aria-keyshortcuts={digit !== null ? String(digit) : undefined}
      >
        <KeyAvatar fingerprint={key.keyId} size={32} />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm">
            <MarkedText text={name} />
          </p>
          {(isOwn || isSsh || verified || clash) && (
            <div className="my-0.5 flex flex-wrap items-center gap-1">
              {isOwn && (
                <span className="bg-secondary text-muted-foreground shrink-0 rounded px-1.5 py-px text-[10.5px] font-medium">
                  {t("actions_badge_you")}
                </span>
              )}
              {isSsh && (
                <span className="bg-secondary text-muted-foreground shrink-0 rounded px-1.5 py-px text-[10.5px] font-medium">
                  {/* i18n-ignore */}
                  SSH
                </span>
              )}
              {verified && (
                <span
                  title={t("keys_verified_chip_title")}
                  className="bg-good/12 text-good shrink-0 rounded px-1.5 py-px text-[10.5px] font-medium"
                >
                  {t("keys_verified_chip")}
                </span>
              )}
              {clash && (
                <span
                  title={clashSentence(clash)}
                  className="bg-warn/12 text-warn shrink-0 rounded px-1.5 py-px text-[10.5px] font-medium"
                >
                  {clashPillLabel(clash)}
                </span>
              )}
            </div>
          )}
          {(detail || keyCount > 1 || shortKeyId) && (
            <p className="text-muted-foreground truncate text-xs">
              {shortKeyId && (
                <span
                  className="font-mono text-[11px]"
                  data-key-id=""
                  title={isSsh ? displayKeyId(key.keyId) : undefined}
                >
                  {shortKeyId}
                  {detail || keyCount > 1 ? " · " : ""}
                </span>
              )}
              <MarkedText
                text={[
                  detail,
                  keyCount > 1
                    ? activeKeyCount < keyCount
                      ? t("actions_keys_of_total", {
                          active: activeKeyCount,
                          count: keyCount,
                        })
                      : tn("actions_keys_count", keyCount)
                    : "",
                ]
                  .filter(Boolean)
                  .join(" · ")}
              />
            </p>
          )}
          {key.keyId === firstBlockedId && blockReason !== null && (
            <p className="text-muted-foreground mt-0.5 text-xs">
              {blockReason}
            </p>
          )}
        </div>
        {/* Never adds the key; not a Tab or list stop. */}
        <button
          type="button"
          tabIndex={-1}
          aria-label={t("keys_key_details")}
          title={t("keys_key_details")}
          className="text-muted-foreground hover:text-foreground hover:bg-raised -my-1 grid size-7 shrink-0 place-items-center rounded-md"
          // Keep focus (and the typed filter) in the input.
          onPointerDown={(e) => e.preventDefault()}
          onClick={(e) => {
            e.stopPropagation();
            setDetailsKey(key);
          }}
        >
          <InfoIcon className="h-4 w-4" />
        </button>
        {digit !== null && <CommandShortcut>{digit}</CommandShortcut>}
      </CommandItem>
    );
  };

  return (
    <div className={inline ? "flex items-start gap-2 py-1 pr-1.5 pl-3" : ""}>
      <label
        htmlFor={inputId}
        className={
          inline
            ? "text-muted-foreground shrink-0 pt-2 text-xs font-medium"
            : "text-muted-foreground mb-1 block text-xs font-medium"
        }
      >
        {label}
      </label>
      {/* Wraps the trigger AND the portaled list so the inline input's
          keystrokes drive cmdk. */}
      <Command
        shouldFilter={false}
        value={highlighted}
        onValueChange={setHighlighted}
        className={cn(
          "overflow-visible bg-transparent",
          inline && "min-w-0 flex-1",
        )}
      >
        {/* Hidden, not closed, under a details page; Back restores it. */}
        <Popover
          open={open && detailsKey === null}
          onOpenChange={(next) => (next ? setOpen(true) : closeDropdown())}
        >
          <PopoverAnchor asChild>
            <div
              ref={containerRef}
              onClick={() => {
                setOpen(true);
                inputRef.current?.focus();
              }}
              onKeyDown={(e) => {
                // Typing on a chip/button goes to the search input; Space
                // and modified keys stay with the focused control.
                if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey)
                  return;
                if (e.key.length !== 1 || e.key === " ") return;
                const input = inputRef.current;
                if (!input || e.target === input) return;
                input.focus();
              }}
              className={cn(
                "flex min-h-9 w-full cursor-text flex-wrap items-center gap-1 rounded-lg px-2 py-1.5 text-sm",
                !inline &&
                  "surface-field focus-within:ring-ring focus-within:ring-1",
              )}
            >
              {selectedKeys.map((key) => {
                const { name, detail } = getKeyDisplay(key);
                return (
                  // The whole chip removes (trigger is a div, so no nested
                  // buttons).
                  <button
                    key={key.keyId}
                    type="button"
                    aria-label={t("actions_remove_recipient", { name })}
                    title={
                      detail
                        ? t("actions_remove_recipient_detail", { name, detail })
                        : t("actions_remove_recipient", { name })
                    }
                    className="bg-secondary text-secondary-foreground hover:bg-destructive/12 hover:text-bad inline-flex max-w-full cursor-pointer items-center gap-1.5 rounded-md py-0.5 pr-1.5 pl-1 text-xs shadow-[inset_0_1px_0_rgb(255_255_255/0.07)] transition-colors"
                    onClick={(e) => {
                      e.stopPropagation();
                      removeRecipient(key.keyId);
                      refocusInput();
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "Backspace" || e.key === "Delete") {
                        e.preventDefault();
                        e.stopPropagation();
                        removeRecipient(key.keyId);
                        refocusInput();
                      }
                    }}
                  >
                    <KeyAvatar fingerprint={key.keyId} size={16} />
                    <span className="min-w-0 truncate">
                      <MarkedText text={name} />
                    </span>
                    {isSshRecord(key) && (
                      <span className="bg-background/60 text-muted-foreground shrink-0 rounded px-1.5 py-px text-[10px] font-medium">
                        {/* i18n-ignore */}
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
                  selectedKeys.length > 0
                    ? undefined
                    : t("actions_add_recipients_placeholder")
                }
                title={t("actions_recipient_input_hint")}
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  if (!open) setOpen(true);
                }}
                onFocus={() => {
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
                  tabIndex={-1}
                  aria-label={t("actions_clear_all_recipients")}
                  title={t("actions_clear_all_recipients")}
                  className="text-muted-foreground hover:text-foreground shrink-0 rounded-sm"
                  onClick={(e) => {
                    e.stopPropagation();
                    onChange([]);
                  }}
                >
                  <XIcon className="h-4 w-4" />
                </button>
              )}
              <button
                type="button"
                tabIndex={-1}
                aria-label={t("actions_toggle_recipient_list")}
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
          {/* No collision flipping, so the list doesn't jump as results
              change. */}
          <PopoverContent
            side={inline ? "bottom" : "top"}
            avoidCollisions={false}
            className="w-(--radix-popover-trigger-width) p-0"
            onOpenAutoFocus={(e) => e.preventDefault()}
            onCloseAutoFocus={(e) => e.preventDefault()}
            // The input is in the ANCHOR; without this, clicks in the
            // trigger count as "outside" and dismiss the list.
            onInteractOutside={(e) => {
              if (
                containerRef.current &&
                e.target instanceof Node &&
                containerRef.current.contains(e.target)
              ) {
                e.preventDefault();
              }
            }}
            // Keep Escape from reaching the slide-over stack's listener.
            onEscapeKeyDown={(e) => e.stopPropagation()}
          >
            <CommandList id={listId} className="h-[300px]">
              <CommandEmpty>{t("actions_no_matches")}</CommandEmpty>
              {recent.length > 0 && (
                <>
                  <CommandGroup heading={t("actions_group_recent")}>
                    {recent.map(renderOption)}
                  </CommandGroup>
                  {(restContacts.length > 0 || restMyKeys.length > 0) && (
                    <CommandSeparator />
                  )}
                </>
              )}
              {restContacts.length > 0 && (
                <CommandGroup heading={t("actions_group_contacts")}>
                  {restContacts.map(renderOption)}
                </CommandGroup>
              )}
              {restContacts.length > 0 && restMyKeys.length > 0 && (
                <CommandSeparator />
              )}
              {restMyKeys.length > 0 && (
                <CommandGroup heading={t("actions_group_my_keys")}>
                  {restMyKeys.map(renderOption)}
                </CommandGroup>
              )}
            </CommandList>
          </PopoverContent>
        </Popover>
      </Command>
      {detailsKey && (
        <KeyDetailsPage
          target={keyDetailsTarget(detailsKey)}
          onBack={() => {
            setDetailsKey(null);
            refocusInput();
          }}
        />
      )}
    </div>
  );
}
