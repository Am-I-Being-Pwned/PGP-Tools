import { useCallback, useRef, useState } from "react";

import { cn } from "@amibeingpwned/ui";
import { Button } from "@amibeingpwned/ui/button";

import { readKeyFile } from "../../lib/binary-armor";
import { t } from "../../lib/i18n";

interface ContactDropZoneProps {
  /** Hand the dropped/pasted/browsed text to the import flow, which
   *  parses it, previews a single key, and bulk-imports a bundle. */
  onKeyText: (text: string) => void;
}

/**
 * Drop target for contact keys.
 *
 * It deliberately does no importing of its own any more: it used to
 * parse and store keys behind the user's back, so a drop produced a
 * toast ("Added 3 contacts") and no way to see whose key had just landed
 * in the keyring. Now every route -- this, the Import button, a global
 * file drop, the workspace banner -- goes through the same preview.
 */
export function ContactDropZone({ onKeyText }: ContactDropZoneProps) {
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback(
    async (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);

      const files = Array.from(e.dataTransfer.files);
      if (files.length > 0) {
        const texts = await Promise.all(files.map(readKeyFile));
        onKeyText(texts.join("\n"));
        return;
      }

      const text = e.dataTransfer.getData("text/plain");
      if (text) onKeyText(text);
    },
    [onKeyText],
  );

  const handlePaste = useCallback(
    (e: React.ClipboardEvent) => {
      const text = e.clipboardData.getData("text/plain");
      if (text.includes("PUBLIC KEY")) {
        e.preventDefault();
        onKeyText(text);
      }
    },
    [onKeyText],
  );

  const handleFileSelect = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const files = Array.from(e.target.files ?? []);
      e.target.value = "";
      if (files.length > 0) {
        const texts = await Promise.all(files.map(readKeyFile));
        onKeyText(texts.join("\n"));
      }
    },
    [onKeyText],
  );

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={handleDrop}
      onPaste={handlePaste}
      tabIndex={0}
      // A flat block, not a dashed box: the first row of the contacts
      // stack (KeysView rounds its corners). A drag over it tints it the
      // "on" green, which is the only cue a drop target needs.
      className={cn(
        "flex items-center gap-3 rounded-[3px] py-2 pr-2 pl-3.5 text-xs transition-colors focus:outline-none",
        dragOver ? "bg-on text-on-foreground" : "bg-card",
      )}
    >
      <p
        className={cn(
          "min-w-0 flex-1",
          dragOver ? "text-on-foreground" : "text-muted-foreground",
        )}
      >
        {t("import_dropzone_text")}
      </p>
      <input
        ref={fileInputRef}
        type="file"
        accept=".asc,.gpg,.pub,.key,.pgp,.txt"
        multiple
        className="hidden"
        onChange={handleFileSelect}
      />
      <Button
        variant="outline"
        size="sm"
        className="shrink-0"
        onClick={() => fileInputRef.current?.click()}
      >
        {t("import_dropzone_browse")}
      </Button>
    </div>
  );
}
