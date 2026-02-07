import { TriangleAlertIcon } from "lucide-react";

import { Alert, AlertDescription } from "@amibeingpwned/ui/alert";

import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import { ContactCard } from "../keys/ContactCard";
import { OutputArea } from "./OutputArea";

interface WorkspaceResultsProps {
  error: string | null;
  output: string;
  binaryOutput: Uint8Array | undefined;
  fileResults: { name: string; data: Uint8Array }[];
  fileName: string;
  operationDone: boolean;
  statusText: string | undefined;
  verifiedSigner: PublicContactKey | ProtectedKeyBlob | null;
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
}: WorkspaceResultsProps) {
  return (
    <div className="min-h-5 space-y-3">
      {error && (
        <Alert variant="destructive">
          <TriangleAlertIcon className="h-4 w-4" />
          <AlertDescription className="text-xs">{error}</AlertDescription>
        </Alert>
      )}

      {verifiedSigner && (
        <ContactCard
          readOnly
          verifiedLabel={statusText ?? "Signature verified"}
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
      />
    </div>
  );
}
