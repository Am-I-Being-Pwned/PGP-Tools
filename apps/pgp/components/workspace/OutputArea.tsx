import { useRef, useState } from "react";
import { CheckIcon, ClipboardIcon, DownloadIcon } from "lucide-react";

import type { FileResult } from "../../lib/utils/download";
import { downloadBinary, downloadText } from "../../lib/utils/download";
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
  const [copied, setCopied] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const preRef = useRef<HTMLPreElement>(null);

  const hasFileResults = fileResults && fileResults.length > 0;
  if (!output && !binaryOutput && !hasFileResults) return null;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(output);
      setCopied(true);
      clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard may fail if panel is not focused
    }
  };

  const handleDownload = () => {
    if (binaryOutput) {
      downloadBinary(binaryOutput, fileName ?? "output.gpg");
    } else {
      downloadText(output, fileName ?? "output.gpg");
    }
  };

  const borderColor = success ? "border-green-500/50" : "border-border";

  return (
    <div
      className={
        fullHeight ? "flex min-h-0 flex-1 flex-col gap-2" : "space-y-2"
      }
    >
      {statusText && <p className="text-xs text-green-400">{statusText}</p>}
      {output && (
        <div className={fullHeight ? "relative min-h-0 flex-1" : "relative"}>
          <div className="absolute top-2 right-4 flex gap-1">
            <button
              onClick={handleCopy}
              className="text-muted-foreground hover:text-foreground rounded p-1 transition-colors"
              title={copied ? "Copied!" : "Copy"}
            >
              {copied ? (
                <CheckIcon className="h-3.5 w-3.5 text-green-400" />
              ) : (
                <ClipboardIcon className="h-3.5 w-3.5" />
              )}
            </button>
            <button
              onClick={handleDownload}
              className="text-muted-foreground hover:text-foreground rounded p-1 transition-colors"
              title="Download"
            >
              <DownloadIcon className="h-3.5 w-3.5" />
            </button>
          </div>
          <pre
            ref={preRef}
            tabIndex={0}
            onKeyDown={(e) => {
              if ((e.ctrlKey || e.metaKey) && e.key === "a" && preRef.current) {
                e.preventDefault();
                const sel = window.getSelection();
                const range = document.createRange();
                range.selectNodeContents(preRef.current);
                sel?.removeAllRanges();
                sel?.addRange(range);
              }
            }}
            className={`bg-muted/50 overflow-auto rounded-md border p-3 pr-16 font-mono text-xs break-all whitespace-pre-wrap focus:outline-none ${fullHeight ? "h-full" : "max-h-48"} ${borderColor}`}
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
