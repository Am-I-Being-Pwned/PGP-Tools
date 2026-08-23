import { useCallback, useRef, useState } from "react";

import { Button } from "@amibeingpwned/ui/button";

import { readKeyFile } from "../../lib/binary-armor";

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
      className={`rounded-md border-2 border-dashed p-3 text-center text-xs transition-colors focus:outline-none ${
        dragOver
          ? "border-primary bg-primary/10"
          : "border-border hover:border-muted-foreground/50"
      }`}
    >
      <p className="text-muted-foreground">
        Drop, paste, or browse for public keys
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
        className="mt-2"
        onClick={() => fileInputRef.current?.click()}
      >
        Browse files
      </Button>
    </div>
  );
}
