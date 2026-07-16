import { useRef } from "react";

import type { FileResult } from "../../lib/utils/download";
import { formatFileSize } from "../../lib/utils/formatting";

interface OutputAreaProps {
  output: string;
  binaryOutput?: Uint8Array;
  fileResults?: FileResult[];
  fileName?: string;
  success?: boolean;
  statusText?: string;
  /** Fill the available height instead of the compact fixed-height output. */
  fullHeight?: boolean;
}

export function OutputArea({
  output,
  binaryOutput,
  fileResults,
  fileName,
  success,
  statusText,
  fullHeight,
}: OutputAreaProps) {
  const preRef = useRef<HTMLPreElement>(null);

  const hasFileResults = fileResults && fileResults.length > 0;
  if (!output && !binaryOutput && !hasFileResults) {
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

  // Compact path (encrypt/sign): nobody reads armored ciphertext, so it is
  // never displayed - a one-line success note is the only feedback, and the
  // panel's bottom Copy/Download buttons are the interface to the output.
  if (!fullHeight) {
    return (
      <div className="space-y-2">
        {statusText && <p className="text-xs text-green-400">{statusText}</p>}
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
