import { useCallback, useRef, useState } from "react";
import { toast } from "sonner";

import { Button } from "@amibeingpwned/ui/button";

import type { PublicContactKey } from "../../lib/storage/contacts";
import { parseKeys } from "../../lib/pgp/wasm";

interface ContactDropZoneProps {
  onImport: (contact: PublicContactKey) => Promise<void>;
  existingKeyIds?: string[];
}

export function ContactDropZone({
  onImport,
  existingKeyIds,
}: ContactDropZoneProps) {
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const splitKeys = (text: string): string[] => {
    const blocks: string[] = [];
    const regex =
      /-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]*?-----END PGP PUBLIC KEY BLOCK-----/g;
    let match;
    while ((match = regex.exec(text)) !== null) {
      blocks.push(match[0]);
    }
    return blocks;
  };

  const tryImportMany = useCallback(
    async (text: string) => {
      setError(null);
      const blocks = splitKeys(text);
      if (blocks.length === 0) {
        setError("No public keys found");
        return;
      }

      let added = 0;
      let skipped = 0;
      let failed = 0;
      let flagged = 0;
      const rejectionReasons: string[] = [];

      for (const block of blocks) {
        // A single armored block may bundle several certs (e.g. a
        // publisher's yearly-rotated keys). Split them so we import the
        // live cert(s) and store each against its own armor -- not the
        // whole blob, which would otherwise encrypt to the first
        // (usually expired) cert.
        let certs;
        try {
          certs = await parseKeys(block);
        } catch {
          failed++;
          continue;
        }

        const usable = certs.filter((c) => c.keyInfo.usableForEncryption);
        if (usable.length === 0) {
          // Nothing live in this block: surface the first cert's reason.
          failed++;
          rejectionReasons.push(
            certs[0]?.keyInfo.policyError ??
              "no usable encryption subkey on this key",
          );
          continue;
        }

        // If a block has a usable cert, the unusable siblings are stale
        // rotations -- drop them silently rather than reporting failures.
        for (const { keyInfo, armored } of usable) {
          if (existingKeyIds?.includes(keyInfo.keyId)) {
            skipped++;
            continue;
          }
          await onImport({
            keyId: keyInfo.keyId,
            userIds: keyInfo.userIds,
            algorithm: keyInfo.algorithm,
            armoredPublicKey: armored,
            addedAt: Date.now(),
            lastUsedAt: Date.now(),
            // Allowed, but flagged (e.g. SHA-1 binding signature).
            securityWarning: keyInfo.securityWarning,
          });
          added++;
          if (keyInfo.securityWarning) flagged++;
        }
      }

      if (added > 0)
        toast.success(`Added ${added} contact${added > 1 ? "s" : ""}`);
      if (flagged > 0) {
        toast.warning(
          `${flagged} key${flagged > 1 ? "s use" : " uses"} weak crypto (SHA-1) and ${
            flagged > 1 ? "were" : "was"
          } flagged - see the warning on the contact.`,
        );
      }
      if (skipped > 0) toast.info(`${skipped} already in contacts`);
      if (failed > 0) {
        const detail = rejectionReasons[0];
        setError(
          detail
            ? `${failed} key${failed > 1 ? "s" : ""} rejected: ${detail}`
            : `${failed} key${failed > 1 ? "s" : ""} failed to import`,
        );
      }
    },
    [onImport, existingKeyIds],
  );

  const handleDrop = useCallback(
    async (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);

      const files = Array.from(e.dataTransfer.files);
      if (files.length > 0) {
        const texts = await Promise.all(files.map((f) => f.text()));
        await tryImportMany(texts.join("\n"));
        return;
      }

      const text = e.dataTransfer.getData("text/plain");
      if (text) await tryImportMany(text);
    },
    [tryImportMany],
  );

  const handlePaste = useCallback(
    (e: React.ClipboardEvent) => {
      const text = e.clipboardData.getData("text/plain");
      if (text.includes("PUBLIC KEY")) {
        e.preventDefault();
        void tryImportMany(text);
      }
    },
    [tryImportMany],
  );

  const handleFileSelect = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const files = Array.from(e.target.files ?? []);
      if (files.length > 0) {
        const texts = await Promise.all(files.map((f) => f.text()));
        await tryImportMany(texts.join("\n"));
      }
      e.target.value = "";
    },
    [tryImportMany],
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
      {error && <p className="text-destructive mt-1">{error}</p>}
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
