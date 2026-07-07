import { TriangleAlertIcon } from "lucide-react";

import { Alert, AlertDescription } from "@amibeingpwned/ui/alert";

import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { FileResult } from "../../lib/utils/download";
import { ContactCard } from "../keys/ContactCard";
import { OutputArea } from "./OutputArea";

interface WorkspaceResultsProps {
  error: string | null;
  output: string;
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
  /** Hold the compact output slot open even when empty (after the first
   *  operation) so clearing the output doesn't collapse the layout. */
  reserve?: boolean;
}

export function WorkspaceResults({
  error,
  output,
  binaryOutput,
  fileResults,
  fileName,
  operationDone,
  statusText,
  verifiedSigner,
  signatureTone = "success",
  fullHeight,
  reserve,
}: WorkspaceResultsProps) {
  const isUnverified = signatureTone === "warning";

  // Nothing to show yet — render nothing rather than reserving a fixed
  // slab of height. That empty reservation is only ever filled in encrypt
  // mode (recipient + sign/zip controls); in sign/verify/decrypt it just
  // pushed the action button away from the controls above it.
  const hasContent =
    !!error ||
    !!verifiedSigner ||
    !!output ||
    !!binaryOutput ||
    fileResults.length > 0;
  if (!fullHeight && !hasContent && !reserve) return null;

  return (
    <div
      className={
        fullHeight ? "flex min-h-0 flex-1 flex-col gap-3" : "space-y-3"
      }
    >
      {error && (
        <Alert variant="destructive">
          <TriangleAlertIcon className="h-4 w-4" />
          <AlertDescription className="text-xs">{error}</AlertDescription>
        </Alert>
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
        output={output}
        binaryOutput={binaryOutput}
        fileResults={fileResults}
        fileName={fileName}
        success={operationDone}
        statusText={verifiedSigner ? undefined : statusText}
        fullHeight={fullHeight}
        reserve={reserve}
      />
    </div>
  );
}
