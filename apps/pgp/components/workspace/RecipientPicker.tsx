import { useState } from "react";
import { ChevronsUpDownIcon, XIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@amibeingpwned/ui/command";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@amibeingpwned/ui/popover";

import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import { orderRecipients } from "../../lib/recipient-ordering";
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
 * as removable chips, the dropdown offers the remaining keys with
 * recently-used ones first, and digits 1-9 quick-pick the nth visible
 * option while the search box is empty.
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

  // Already-selected recipients don't reappear in the dropdown.
  const selectedSet = new Set(selectedKeyIds);
  const available = allKeys.filter((k) => !selectedSet.has(k.keyId));
  const { recent, rest } = orderRecipients(available, recentKeyIds);
  const contactIds = new Set(contacts.map((c) => c.keyId));
  const restContacts = rest.filter((k) => contactIds.has(k.keyId));
  const restMyKeys = rest.filter((k) => !contactIds.has(k.keyId));
  // Render order, flattened -- what the digit shortcuts index into.
  const visibleKeys = [...recent, ...restContacts, ...restMyKeys];

  const addRecipient = (keyId: string) => {
    onChange([...selectedKeyIds, keyId]);
    setSearch("");
  };
  const removeRecipient = (keyId: string) => {
    onChange(selectedKeyIds.filter((id) => id !== keyId));
  };

  const handleInputKeyDown = (e: React.KeyboardEvent) => {
    // Escape closes the dropdown ONLY -- stop it here so the surrounding
    // view/slide-over (document-level listener) doesn't also close.
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      setOpen(false);
      return;
    }
    // Backspace in the empty search box pops the last chip, like Linear.
    if (e.key === "Backspace" && search === "" && selectedKeyIds.length > 0) {
      e.preventDefault();
      onChange(selectedKeyIds.slice(0, -1));
      return;
    }
    // Digits quick-pick the nth visible option, but only while the search
    // box is EMPTY -- typing numbers into a query must never trigger picks.
    if (search === "" && /^[1-9]$/.test(e.key)) {
      const index = Number(e.key) - 1;
      if (index < visibleKeys.length) {
        e.preventDefault();
        addRecipient(visibleKeys[index].keyId);
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
    return (
      <CommandItem
        key={key.keyId}
        value={
          detail ? `${name} ${detail} ${key.keyId}` : `${name} ${key.keyId}`
        }
        onSelect={() => addRecipient(key.keyId)}
        className="gap-2"
      >
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm">{name}</p>
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
      <label className="text-muted-foreground mb-1 block text-xs font-medium">
        {label}
      </label>
      {selectedKeys.length > 0 && (
        <div className="mb-1.5 flex flex-wrap gap-1">
          {selectedKeys.map((key) => {
            const { name, detail } = getKeyDisplay(key);
            return (
              <span
                key={key.keyId}
                title={detail || undefined}
                className="bg-secondary text-secondary-foreground inline-flex max-w-full items-center gap-1 rounded-md border px-2 py-0.5 text-xs"
              >
                <span className="truncate">{name}</span>
                <button
                  type="button"
                  aria-label={`Remove ${name}`}
                  className="text-muted-foreground hover:text-foreground -mr-0.5 shrink-0 rounded-sm"
                  onClick={() => removeRecipient(key.keyId)}
                >
                  <XIcon className="h-3 w-3" />
                </button>
              </span>
            );
          })}
        </div>
      )}
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            variant="outline"
            role="combobox"
            aria-expanded={open}
            className="h-auto w-full min-w-0 justify-between py-1.5 font-normal"
          >
            <span className="text-muted-foreground text-sm">
              {selectedKeys.length > 0
                ? "Add another recipient..."
                : "Select recipients..."}
            </span>
            <ChevronsUpDownIcon className="ml-2 h-4 w-4 shrink-0 opacity-50" />
          </Button>
        </PopoverTrigger>
        {/* Pin the list ABOVE the trigger and disable collision flipping so
            it doesn't jump between top/bottom as the result count changes
            while searching. */}
        <PopoverContent
          side="top"
          avoidCollisions={false}
          className="w-(--radix-popover-trigger-width) p-0"
          // Radix's own Escape handling runs on a document capture
          // listener; stop the event there too so it can't bubble on to
          // the slide-over stack's document listener.
          onEscapeKeyDown={(e) => e.stopPropagation()}
        >
          <Command>
            <CommandInput
              placeholder="Search..."
              value={search}
              onValueChange={setSearch}
              onKeyDown={handleInputKeyDown}
            />
            {/* Fixed height (not just max-h) so the list stays a constant
                size and doesn't grow/shrink as search filters the results. */}
            <CommandList className="h-[300px]">
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
          </Command>
        </PopoverContent>
      </Popover>
    </div>
  );
}
