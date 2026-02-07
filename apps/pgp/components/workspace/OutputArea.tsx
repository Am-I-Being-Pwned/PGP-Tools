import { useRef, useState } from "react";
import { CheckIcon, ClipboardIcon, DownloadIcon } from "lucide-react";

interface OutputAreaProps {
  output: string;
  binaryOutput?: Uint8Array;
  fileResults?: { name: string; data: Uint8Array }[];
  fileName?: string;
  success?: boolean;
  statusText?: string;
}

export function OutputArea({
  output,
  binaryOutput,
  fileResults,
  fileName,
  success,
  statusText,
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
    const blob = binaryOutput
      ? new Blob([binaryOutput.slice()], { type: "application/octet-stream" })
      : new Blob([output], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName ?? "output.gpg";
    a.click();
    URL.revokeObjectURL(url);
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const borderColor = success ? "border-green-500/50" : "border-border";

  return (
    <div className="space-y-2">
      {statusText && <p className="text-xs text-green-400">{statusText}</p>}
      {output && (
        <div className="relative">
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
            className={`bg-muted/50 max-h-48 overflow-auto rounded-md border p-3 pr-16 font-mono text-xs break-all whitespace-pre-wrap focus:outline-none ${borderColor}`}
          >
            {output}
          </pre>
        </div>
      )}
      {binaryOutput && !output && !hasFileResults && !statusText && (
        <p className="text-muted-foreground text-sm">
          {fileName ?? "output.gpg"} - {formatSize(binaryOutput.length)}
        </p>
      )}
    </div>
  );
}
