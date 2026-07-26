import { useState } from "react";
import { CheckIcon, ChevronsUpDownIcon } from "lucide-react";

import { cn } from "@amibeingpwned/ui";
import { Button } from "@amibeingpwned/ui/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@amibeingpwned/ui/command";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@amibeingpwned/ui/popover";

import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import { formatKeyDisplayName } from "../../lib/utils/key-naming";
import { KeyDetailsButton } from "../keys/KeyDetailsButton";

type AnyKey = ProtectedKeyBlob | PublicContactKey;

interface KeySelectorProps {
  label: string;
  keys?: AnyKey[];
  contacts?: PublicContactKey[];
  myKeys?: ProtectedKeyBlob[];
  selectedKeyId: string | null;
  onSelect: (keyId: string) => void;
  emptyText?: string;
  emptyAction?: () => void;
  emptyActionLabel?: string;
}

function getKeyDisplay(key: AnyKey): { name: string; detail: string } {
  const userId = key.userIds[0];
  if (!userId) return { name: key.keyId.slice(-8).toUpperCase(), detail: "" };
  return formatKeyDisplayName(userId);
}

export function KeySelector({
  label,
  keys,
  contacts,
  myKeys,
  selectedKeyId,
  onSelect,
  emptyText = "No keys available",
  emptyAction,
  emptyActionLabel,
}: KeySelectorProps) {
  const [open, setOpen] = useState(false);

  const hasGroups =
    !keys && ((contacts?.length ?? 0) > 0 || (myKeys?.length ?? 0) > 0);
  const flatKeys = keys ?? [...(contacts ?? []), ...(myKeys ?? [])];

  if (flatKeys.length === 0) {
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

  const selectedKey = flatKeys.find((k) => k.keyId === selectedKeyId);
  const selectedDisplay = selectedKey ? getKeyDisplay(selectedKey) : null;

  return (
    <div>
      <label className="text-muted-foreground mb-1 block text-xs font-medium">
        {label}
      </label>
      <div className="flex items-stretch gap-1.5">
        <Popover open={open} onOpenChange={setOpen}>
          <PopoverTrigger asChild>
            <Button
              variant="outline"
              role="combobox"
              aria-expanded={open}
              className="h-auto min-w-0 flex-1 justify-between py-1.5 font-normal"
            >
              {selectedDisplay ? (
                <div className="min-w-0 text-left">
                  <p className="truncate text-sm">{selectedDisplay.name}</p>
                  {selectedDisplay.detail && (
                    <p className="text-muted-foreground truncate text-xs">
                      {selectedDisplay.detail}
                    </p>
                  )}
                </div>
              ) : (
                <span className="text-muted-foreground text-sm">
                  Select a key...
                </span>
              )}
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
          >
            <Command
              onKeyDown={(e) => {
                // mod+Enter is the global Run shortcut, never a pick:
                // preventDefault so cmdk skips its own Enter handler (it
                // bails on defaultPrevented), close the popover, and let
                // the event bubble to the window-level shortcut listener.
                if (
                  e.key === "Enter" &&
                  (e.metaKey || e.ctrlKey || e.altKey)
                ) {
                  e.preventDefault();
                  setOpen(false);
                }
              }}
            >
              <CommandInput placeholder="Search..." />
              {/* Fixed height (not just max-h) so the list stays a constant
                size and doesn't grow/shrink as search filters the results. */}
              <CommandList className="h-[300px]">
                <CommandEmpty>No keys found</CommandEmpty>
                {hasGroups ? (
                  <>
                    {contacts && contacts.length > 0 && (
                      <CommandGroup heading="Contacts">
                        {contacts.map((key) => (
                          <KeyOption
                            key={key.keyId}
                            keyData={key}
                            selected={key.keyId === selectedKeyId}
                            onSelect={() => {
                              onSelect(key.keyId);
                              setOpen(false);
                            }}
                          />
                        ))}
                      </CommandGroup>
                    )}
                    {contacts &&
                      contacts.length > 0 &&
                      myKeys &&
                      myKeys.length > 0 && <CommandSeparator />}
                    {myKeys && myKeys.length > 0 && (
                      <CommandGroup heading="My Keys">
                        {myKeys.map((key) => (
                          <KeyOption
                            key={key.keyId}
                            keyData={key}
                            selected={key.keyId === selectedKeyId}
                            onSelect={() => {
                              onSelect(key.keyId);
                              setOpen(false);
                            }}
                          />
                        ))}
                      </CommandGroup>
                    )}
                  </>
                ) : (
                  <CommandGroup>
                    {flatKeys.map((key) => (
                      <KeyOption
                        key={key.keyId}
                        keyData={key}
                        selected={key.keyId === selectedKeyId}
                        onSelect={() => {
                          onSelect(key.keyId);
                          setOpen(false);
                        }}
                      />
                    ))}
                  </CommandGroup>
                )}
              </CommandList>
            </Command>
          </PopoverContent>
        </Popover>
        {selectedKey && <KeyDetailsButton keyData={selectedKey} />}
      </div>
    </div>
  );
}

function KeyOption({
  keyData,
  selected,
  onSelect,
}: {
  keyData: AnyKey;
  selected: boolean;
  onSelect: () => void;
}) {
  const { name, detail } = getKeyDisplay(keyData);

  return (
    <CommandItem
      value={detail ? `${name} ${detail}` : name}
      onSelect={onSelect}
      className="gap-2"
    >
      <CheckIcon
        className={cn(
          "h-4 w-4 shrink-0",
          selected ? "opacity-100" : "opacity-0",
        )}
      />
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm">{name}</p>
        {detail && (
          <p className="text-muted-foreground truncate text-xs">{detail}</p>
        )}
      </div>
    </CommandItem>
  );
}
