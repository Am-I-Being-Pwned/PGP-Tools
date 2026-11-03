import { useState } from "react";
import { CheckIcon, ChevronsUpDownIcon } from "lucide-react";

import {
  Button,
  cn,
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@amibeingpwned/ui";

import { KeyDetailsButton } from "~/components/keys/KeyDetailsButton";
import { KeyAvatar } from "~/components/shared/KeyAvatar";
import { MarkedText } from "~/components/shared/MarkedText";
import { t } from "~/lib/i18n";
import type { PublicContactKey } from "~/lib/storage/contacts";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import type { StoredKey } from "~/lib/storage/stored-key";
import { displayUserId, formatKeyDisplayName } from "~/lib/utils/key-naming";

interface KeySelectorProps {
  label: string;
  keys?: StoredKey[];
  contacts?: PublicContactKey[];
  myKeys?: ProtectedKeyBlob[];
  selectedKeyId: string | null;
  onSelect: (keyId: string) => void;
  emptyText?: string;
  emptyAction?: () => void;
  emptyActionLabel?: string;
  /** Inside a card row (the From line): label becomes the accessible name. */
  inline?: boolean;
}

function getKeyDisplay(key: StoredKey): { name: string; detail: string } {
  const userId = displayUserId(key);
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
  emptyText,
  emptyAction,
  emptyActionLabel,
  inline = false,
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
          {emptyText ?? t("actions_no_keys_available")}
          {emptyAction && (
            <>
              {" "}
              <button
                type="button"
                // Not passed directly: the MouseEvent would become a truthy importPrefill.
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

  const selectedKey = flatKeys.find((k) => k.keyId === selectedKeyId);
  const selectedDisplay = selectedKey ? getKeyDisplay(selectedKey) : null;

  const list = (
    <>
      {/* No collision flipping: the list must not jump as search filters it. */}
      <PopoverContent
        side={inline ? "bottom" : "top"}
        avoidCollisions={false}
        className="w-(--radix-popover-trigger-width) p-0"
      >
        <Command
          onKeyDown={(e) => {
            // mod+Enter is the global Run shortcut, never a pick: cmdk bails on
            // defaultPrevented, and the event still bubbles to the window.
            if (e.key === "Enter" && (e.metaKey || e.ctrlKey || e.altKey)) {
              e.preventDefault();
              setOpen(false);
            }
          }}
        >
          <CommandInput placeholder={t("actions_search_placeholder")} />
          <CommandList className="h-[300px]">
            <CommandEmpty>{t("actions_no_keys_found")}</CommandEmpty>
            {hasGroups ? (
              <>
                {contacts && contacts.length > 0 && (
                  <CommandGroup heading={t("actions_group_contacts")}>
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
                  <CommandGroup heading={t("actions_group_my_keys")}>
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
    </>
  );

  if (inline) {
    return (
      <div className="flex min-w-0 flex-1 items-center gap-0.5">
        <Popover open={open} onOpenChange={setOpen}>
          <PopoverTrigger asChild>
            <button
              type="button"
              role="combobox"
              aria-expanded={open}
              aria-label={label}
              className="hover:bg-accent focus-visible:ring-ring/50 flex min-w-0 flex-1 items-center gap-2.5 rounded-md py-1 pr-1.5 pl-1 text-left text-sm outline-none focus-visible:ring-2"
            >
              {selectedKey && selectedDisplay ? (
                <>
                  <KeyAvatar fingerprint={selectedKey.keyId} size={16} />
                  <span className="min-w-0 flex-1 truncate">
                    <MarkedText text={selectedDisplay.name} />
                    {selectedDisplay.detail && (
                      <span className="text-muted-foreground ml-1.5 text-xs">
                        <MarkedText text={selectedDisplay.detail} />
                      </span>
                    )}
                  </span>
                </>
              ) : (
                <span className="text-muted-foreground min-w-0 flex-1 truncate">
                  {t("actions_select_key_placeholder")}
                </span>
              )}
              <ChevronsUpDownIcon className="h-3.5 w-3.5 shrink-0 opacity-50" />
            </button>
          </PopoverTrigger>
          {list}
        </Popover>
        {selectedKey && <KeyDetailsButton keyData={selectedKey} subtle />}
      </div>
    );
  }

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
              className="h-auto min-w-0 flex-1 justify-between py-1.5 pl-2 font-normal"
            >
              {selectedKey && selectedDisplay ? (
                <div className="flex min-w-0 items-center gap-2.5 text-left">
                  <KeyAvatar fingerprint={selectedKey.keyId} size={32} />
                  <div className="min-w-0">
                    <p className="truncate text-sm">
                      <MarkedText text={selectedDisplay.name} />
                    </p>
                    {selectedDisplay.detail && (
                      <p className="text-muted-foreground truncate text-xs">
                        <MarkedText text={selectedDisplay.detail} />
                      </p>
                    )}
                  </div>
                </div>
              ) : (
                <span className="text-muted-foreground pl-1 text-sm">
                  {t("actions_select_key_placeholder")}
                </span>
              )}
              <ChevronsUpDownIcon className="ml-2 h-4 w-4 shrink-0 opacity-50" />
            </Button>
          </PopoverTrigger>
          {list}
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
  keyData: StoredKey;
  selected: boolean;
  onSelect: () => void;
}) {
  const { name, detail } = getKeyDisplay(keyData);

  return (
    <CommandItem
      value={detail ? `${name} ${detail}` : name}
      onSelect={onSelect}
      className="gap-2.5"
    >
      <KeyAvatar fingerprint={keyData.keyId} size={32} />
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm">
          <MarkedText text={name} />
        </p>
        {detail && (
          <p className="text-muted-foreground truncate text-xs">
            <MarkedText text={detail} />
          </p>
        )}
      </div>
      <CheckIcon
        className={cn(
          "text-good h-4 w-4 shrink-0",
          selected ? "opacity-100" : "opacity-0",
        )}
      />
    </CommandItem>
  );
}
