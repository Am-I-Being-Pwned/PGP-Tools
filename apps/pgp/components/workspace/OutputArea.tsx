import { useRef, useState } from "react";
import { ChevronRightIcon, LockIcon } from "lucide-react";

import type { FileResult } from "../../lib/utils/download";
import { formatFileSize } from "../../lib/utils/formatting";

interface OutputAreaProps {
  output: string;
  binaryOutput?: Uint8Array;
  fileResults?: FileResult[];
  fileName?: string;
  success?: boolean;
  statusText?: string;
  /** Fill the available height instead of the compact fixed-height preview. */
  fullHeight?: boolean;
  /** Compact mode: when there's no output, hold the summary row's footprint
   *  (as an invisible placeholder) instead of collapsing to nothing, so the
   *  layout doesn't jump when the output is cleared and re-produced. */
  reserve?: boolean;
}

// Friendly label derived from the armor header, so the collapsed summary
// says what the ciphertext actually is without needing the mode passed in.
function outputLabel(armored: string): string {
  const kind = /-----BEGIN PGP (.+?)-----/.exec(armored)?.[1] ?? "";
  if (kind === "MESSAGE") return "Encrypted message";
  if (kind === "SIGNED MESSAGE") return "Signed message";
  if (kind === "SIGNATURE") return "Signature";
  if (kind.includes("PUBLIC KEY")) return "Public key";
  if (kind.includes("PRIVATE KEY")) return "Private key";
  return "PGP output";
}

export function OutputArea({
  output,
  binaryOutput,
  fileResults,
  fileName,
  success,
  statusText,
  fullHeight,
  reserve,
}: OutputAreaProps) {
  const [expanded, setExpanded] = useState(false);
  const preRef = useRef<HTMLPreElement>(null);

  const hasFileResults = fileResults && fileResults.length > 0;
  if (!output && !binaryOutput && !hasFileResults) {
    // Reserve the collapsed summary row's exact height with an invisible
    // clone, so clearing the output (e.g. on a recipient change) keeps the
    // slot open rather than collapsing it and jumping the controls.
    if (!fullHeight && reserve) {
      return (
        <div aria-hidden className="invisible space-y-2">
          <div className="border-border overflow-hidden rounded-md border">
            <div className="flex w-full items-center justify-between gap-2 px-3 py-2">
              <span className="flex items-center gap-2 text-xs">
                <LockIcon className="h-3.5 w-3.5 shrink-0" />
                <span className="font-medium">Encrypted message</span>
              </span>
              <span className="flex items-center gap-1 text-xs">
                Preview
                <ChevronRightIcon className="h-3.5 w-3.5" />
              </span>
            </div>
          </div>
        </div>
      );
    }
    return null;
  }

  const selectAllOnCtrlA = (e: React.KeyboardEvent<HTMLPreElement>) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "a" && preRef.current) {
      e.preventDefault();
      const sel = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(preRef.current);
      sel?.removeAllRanges();
      sel?.addRange(range);
    }
  };

  // Compact path (encrypt/sign): nobody reads armored ciphertext, so keep it
  // out of the way behind a one-line summary that expands on demand. The
  // Download/Copy actions live in the panel's bottom button, not in here.
  if (!fullHeight) {
    return (
      <div className="space-y-2">
        {statusText && <p className="text-xs text-green-400">{statusText}</p>}
        {output && (
          <div className="border-border overflow-hidden rounded-md border">
            <button
              type="button"
              onClick={() => setExpanded((e) => !e)}
              aria-expanded={expanded}
              className="hover:bg-muted/50 flex w-full items-center justify-between gap-2 px-3 py-2 text-left transition-colors"
            >
              <span className="flex items-center gap-2 text-xs">
                <LockIcon className="h-3.5 w-3.5 shrink-0 text-green-400" />
                <span className="font-medium">{outputLabel(output)}</span>
                <span className="text-muted-foreground">
                  · {formatFileSize(output.length)}
                </span>
              </span>
              <span className="text-muted-foreground flex items-center gap-1 text-xs">
                Preview
                <ChevronRightIcon
                  className={`h-3.5 w-3.5 transition-transform ${
                    expanded ? "rotate-90" : ""
                  }`}
                />
              </span>
            </button>
            {expanded && (
              <pre
                ref={preRef}
                tabIndex={0}
                onKeyDown={selectAllOnCtrlA}
                className="border-border bg-muted/50 max-h-48 overflow-auto border-t p-3 font-mono text-xs break-all whitespace-pre-wrap focus:outline-none"
              >
                {output}
              </pre>
            )}
          </div>
        )}
        {binaryOutput && !output && !hasFileResults && !statusText && (
          <p className="text-muted-foreground text-sm">
            {fileName ?? "output.gpg"} - {formatFileSize(binaryOutput.length)}
          </p>
        )}
      </div>
    );
  }

  // Full-height path (decrypt): the plaintext is meant to be read, so give it
  // the whole panel. Download/Copy live in the panel's bottom action bar, to
  // match the encrypt/sign flow.
  const borderColor = success ? "border-green-500/50" : "border-border";

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2">
      {statusText && <p className="text-xs text-green-400">{statusText}</p>}
      {output && (
        <div className="relative min-h-0 flex-1">
          <pre
            ref={preRef}
            tabIndex={0}
            onKeyDown={selectAllOnCtrlA}
            className={`bg-muted/50 h-full overflow-auto rounded-md border p-3 font-mono text-xs break-all whitespace-pre-wrap focus:outline-none ${borderColor}`}
          >
            {output}
          </pre>
        </div>
      )}
      {binaryOutput && !output && !hasFileResults && !statusText && (
        <p className="text-muted-foreground text-sm">
          {fileName ?? "output.gpg"} - {formatFileSize(binaryOutput.length)}
        </p>
      )}
    </div>
  );
}
