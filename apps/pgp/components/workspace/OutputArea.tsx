import { useCallback } from "react";

import { Block, BlockStack } from "@amibeingpwned/ui";

import { t } from "~/lib/i18n";
import type { FileResult } from "~/lib/utils/download";
import { formatFileSize } from "~/lib/utils/formatting";
import { showLoneCarriageReturns } from "~/lib/utils/line-breaks";

interface OutputAreaProps {
  /** UNCONTROLLED: plaintext is written to `textContent` by the owning hook,
   *  never rendered as a React child (`useWorkspace`, SECURITY.md §8.11). */
  outputElRef: React.MutableRefObject<HTMLPreElement | null>;
  getOutput: () => string;
  hasOutput: boolean;
  binaryOutput?: Uint8Array;
  fileResults?: FileResult[];
  fileName?: string;
  success?: boolean;
  statusText?: string;
  fullHeight?: boolean;
  /** Replaces the message rather than stacking under it. */
  showTranslation?: boolean;
  /** Same ref + imperative `textContent` contract as the output: it is a
   *  second copy of the same plaintext. */
  translationElRef?: React.MutableRefObject<HTMLPreElement | null>;
  getTranslation?: () => string;
  footer?: React.ReactNode;
  corner?: React.ReactNode;
  header?: React.ReactNode;
}

export function OutputArea({
  outputElRef,
  getOutput,
  hasOutput,
  binaryOutput,
  fileResults,
  fileName,
  statusText,
  fullHeight,
  showTranslation,
  translationElRef,
  getTranslation,
  footer,
  corner,
  header,
}: OutputAreaProps) {
  // Re-seed on every (re)mount: the node really unmounts, and an
  // imperatively-written node comes back empty.
  const attachOutput = useCallback(
    (el: HTMLPreElement | null) => {
      outputElRef.current = el;
      if (el) el.textContent = showLoneCarriageReturns(getOutput());
    },
    [outputElRef, getOutput],
  );

  const attachTranslation = useCallback(
    (el: HTMLPreElement | null) => {
      if (translationElRef) translationElRef.current = el;
      if (el && getTranslation) el.textContent = getTranslation();
    },
    [translationElRef, getTranslation],
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

  // Compact path (encrypt/sign): armored ciphertext is never displayed.
  if (!fullHeight) {
    return (
      <div className="space-y-2">
        {statusText && <p className="text-good text-xs">{statusText}</p>}
        {binaryOutput && !hasOutput && !hasFileResults && !statusText && (
          <p className="text-muted-foreground text-sm">
            {t("workspace_output_size_line", {
              name: fileName ?? "output.gpg",
              size: formatFileSize(binaryOutput.length),
            })}
          </p>
        )}
      </div>
    );
  }

  const cornerInset = corner ? "pr-14" : "";

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2">
      {hasOutput ? (
        <BlockStack className="min-h-0 flex-1">
          {header}
          {statusText && (
            <Block className="text-good shrink-0 bg-[#15231b] px-3.5 py-2.5 text-xs">
              {statusText}
            </Block>
          )}
          <Block className="relative min-h-0 flex-1">
            {/* No React children on purpose: plaintext never enters the
                element tree. */}
            {showTranslation ? (
              <pre
                key="translation"
                ref={attachTranslation}
                tabIndex={0}
                className={`h-full overflow-auto p-3 pb-11 font-mono text-xs break-all whitespace-pre-wrap focus:outline-none ${cornerInset}`}
              />
            ) : (
              <pre
                key="output"
                ref={attachOutput}
                tabIndex={0}
                onKeyDown={selectAllOnCtrlA}
                className={`h-full overflow-auto p-3 pb-11 font-mono text-xs break-all whitespace-pre-wrap focus:outline-none ${cornerInset}`}
              />
            )}
            {corner && (
              <div className="pointer-events-none absolute top-2 right-2 flex items-center gap-2">
                {corner}
              </div>
            )}
            {footer && (
              <div className="pointer-events-none absolute inset-x-2 bottom-2 flex items-center justify-end gap-2">
                {footer}
              </div>
            )}
          </Block>
        </BlockStack>
      ) : (
        <>
          {header}
          {statusText && <p className="text-good text-xs">{statusText}</p>}
        </>
      )}
      {binaryOutput && !hasOutput && !hasFileResults && !statusText && (
        <p className="text-muted-foreground text-sm">
          {t("workspace_output_size_line", {
            name: fileName ?? "output.gpg",
            size: formatFileSize(binaryOutput.length),
          })}
        </p>
      )}
    </div>
  );
}
