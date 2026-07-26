import { useCallback } from "react";

import type { FileResult } from "../../lib/utils/download";
import { formatFileSize } from "../../lib/utils/formatting";

interface OutputAreaProps {
  /** The result `<pre>`. It is UNCONTROLLED: the plaintext is written to
   *  `textContent` by the owning hook, never rendered as a React child,
   *  so it stays out of render state. See the output block in
   *  `useWorkspaceState` for why. */
  outputElRef: React.MutableRefObject<HTMLPreElement | null>;
  /** Read the result text at the point of use. */
  getOutput: () => string;
  /** Derived, non-sensitive: there is a textual result. */
  hasOutput: boolean;
  binaryOutput?: Uint8Array;
  fileResults?: FileResult[];
  fileName?: string;
  success?: boolean;
  statusText?: string;
  /** Fill the available height instead of the compact fixed-height output. */
  fullHeight?: boolean;
}

export function OutputArea({
  outputElRef,
  getOutput,
  hasOutput,
  binaryOutput,
  fileResults,
  fileName,
  success,
  statusText,
  fullHeight,
}: OutputAreaProps) {
  // Callback ref: publish the node to the owning hook and seed its text
  // from the ref on every (re)mount. The node genuinely unmounts (the
  // compact encrypt/sign path renders no `<pre>` at all, and Back tears
  // the full-height view down), and an imperatively-written node comes
  // back empty -- re-seeding is what makes the result survive those
  // swaps, exactly as `WorkspaceInput`'s `attachInput` does for the box.
  const attachOutput = useCallback(
    (el: HTMLPreElement | null) => {
      outputElRef.current = el;
      if (el) el.textContent = getOutput();
    },
    [outputElRef, getOutput],
  );

  const hasFileResults = fileResults && fileResults.length > 0;
  if (!hasOutput && !binaryOutput && !hasFileResults) {
    return null;
  }

  const selectAllOnCtrlA = (e: React.KeyboardEvent<HTMLPreElement>) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "a" && outputElRef.current) {
      e.preventDefault();
      const sel = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(outputElRef.current);
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
        {binaryOutput && !hasOutput && !hasFileResults && !statusText && (
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
      {hasOutput && (
        <div className="relative min-h-0 flex-1">
          {/* No React children on purpose: `attachOutput` writes the text
              imperatively so the plaintext never enters the element tree. */}
          <pre
            ref={attachOutput}
            tabIndex={0}
            onKeyDown={selectAllOnCtrlA}
            className={`bg-muted/50 h-full overflow-auto rounded-md border p-3 font-mono text-xs break-all whitespace-pre-wrap focus:outline-none ${borderColor}`}
          />
        </div>
      )}
      {binaryOutput && !hasOutput && !hasFileResults && !statusText && (
        <p className="text-muted-foreground text-sm">
          {fileName ?? "output.gpg"} - {formatFileSize(binaryOutput.length)}
        </p>
      )}
    </div>
  );
}
