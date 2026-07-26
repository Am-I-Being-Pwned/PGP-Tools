import { useState } from "react";
import { TriangleAlertIcon } from "lucide-react";

import { Alert, AlertDescription } from "@amibeingpwned/ui/alert";

import type { PresentedError, RemedyAction } from "../../lib/errors/present";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { FileResult } from "../../lib/utils/download";
import { ContactCard } from "../keys/ContactCard";
import { OutputArea } from "./OutputArea";

/** The curated error alert: message up front, the raw error text behind
 *  a "Show technical details" toggle, and (when the parent wires a
 *  handler) a small remedy action button. */
function ErrorAlert({
  error,
  onRemedy,
}: {
  error: PresentedError;
  onRemedy?: (action: RemedyAction) => void;
}) {
  const [showDetail, setShowDetail] = useState(false);
  const remedy = onRemedy ? error.remedy : undefined;

  // Soft entry: a fast fade/slide keeps a fresh error from hard-jumping
  // the layout. No reserved space (deliberately removed); reduced-motion
  // users get an instant appearance instead.
  return (
    <Alert
      variant="destructive"
      className="animate-in fade-in slide-in-from-top-1 duration-100 motion-reduce:animate-none"
    >
      <TriangleAlertIcon className="h-4 w-4" />
      <AlertDescription className="text-xs">
        <p>{error.message}</p>
        {(remedy ?? error.detail) && (
          <div className="mt-1.5 flex items-center gap-3">
            {remedy && (
              <button
                type="button"
                className="font-medium underline underline-offset-2"
                onClick={() => onRemedy?.(remedy.action)}
              >
                {remedy.label}
              </button>
            )}
            {error.detail && (
              <button
                type="button"
                className="text-muted-foreground underline underline-offset-2"
                onClick={() => setShowDetail((v) => !v)}
              >
                {showDetail ? "Hide technical details" : "Show technical details"}
              </button>
            )}
          </div>
        )}
        {showDetail && error.detail && (
          <p className="text-muted-foreground mt-1.5 font-mono break-all">
            {error.detail}
          </p>
        )}
      </AlertDescription>
    </Alert>
  );
}

interface WorkspaceResultsProps {
  error: PresentedError | null;
  /** Maps a remedy action (e.g. "import-key") to an existing handler.
   *  When absent, remedies render as message-only guidance. */
  onRemedy?: (action: RemedyAction) => void;
  /** Uncontrolled result node + reader; see `OutputArea`. */
  outputElRef: React.MutableRefObject<HTMLPreElement | null>;
  getOutput: () => string;
  hasOutput: boolean;
  binaryOutput: Uint8Array | undefined;
  fileResults: FileResult[];
  fileName: string;
  operationDone: boolean;
  statusText: string | undefined;
  verifiedSigner: PublicContactKey | ProtectedKeyBlob | null;
  /** Tone of the signer card: green when verified, orange when signed but
   *  unverifiable (signer's key not held). */
  signatureTone?: "success" | "warning";
  /** Fill the available height (used by the full-screen result view). */
  fullHeight?: boolean;
}

export function WorkspaceResults({
  error,
  onRemedy,
  outputElRef,
  getOutput,
  hasOutput,
  binaryOutput,
  fileResults,
  fileName,
  operationDone,
  statusText,
  verifiedSigner,
  signatureTone = "success",
  fullHeight,
}: WorkspaceResultsProps) {
  const isUnverified = signatureTone === "warning";

  const hasContent =
    !!error ||
    !!verifiedSigner ||
    hasOutput ||
    !!binaryOutput ||
    fileResults.length > 0;
  if (!fullHeight && !hasContent) return null;

  return (
    <div
      className={
        fullHeight ? "flex min-h-0 flex-1 flex-col gap-3" : "space-y-3"
      }
    >
      {/* Key on the message so a new error starts with details collapsed. */}
      {error && (
        <ErrorAlert key={error.message} error={error} onRemedy={onRemedy} />
      )}

      {verifiedSigner && (
        <ContactCard
          readOnly
          verifiedTone={signatureTone}
          verifiedLabel={
            isUnverified ? "Unverified" : (statusText ?? "Signature verified")
          }
          note={isUnverified ? statusText : undefined}
          contact={
            "armoredPublicKey" in verifiedSigner
              ? verifiedSigner
              : {
                  keyId: verifiedSigner.keyId,
                  userIds: verifiedSigner.userIds,
                  algorithm: verifiedSigner.algorithm,
                  armoredPublicKey: verifiedSigner.publicKeyArmored,
                  addedAt: 0,
                  lastUsedAt: 0,
                }
          }
        />
      )}

      <OutputArea
        outputElRef={outputElRef}
        getOutput={getOutput}
        hasOutput={hasOutput}
        binaryOutput={binaryOutput}
        fileResults={fileResults}
        fileName={fileName}
        success={operationDone}
        statusText={verifiedSigner ? undefined : statusText}
        fullHeight={fullHeight}
      />
    </div>
  );
}
