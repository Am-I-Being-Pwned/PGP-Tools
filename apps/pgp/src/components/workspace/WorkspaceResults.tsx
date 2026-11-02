import { useState } from "react";
import { SearchIcon, TriangleAlertIcon } from "lucide-react";

import { Alert, AlertDescription, Button } from "@amibeingpwned/ui";

import { KeyDetailsButton } from "~/components/keys/KeyDetailsButton";
import { useContacts, useKeyring } from "~/hooks";
import type { PresentedError, RemedyAction } from "~/lib/errors/present";
import { t } from "~/lib/i18n";
import { KEYSERVER_HOST } from "~/lib/import/keyserver";
import { DetectedKeyBanner } from "./DetectedKeyBanner";
import { OutputArea } from "./OutputArea";
import { signerCardState } from "./signer-card";
import { SignerCard } from "./SignerCard";
import type { Workspace } from "./useWorkspace";
import type { WorkspaceFlags } from "./workspace-view";

function ErrorAlert({
  error,
  onRemedy,
}: {
  error: PresentedError;
  onRemedy?: (action: RemedyAction) => void;
}) {
  const [showDetail, setShowDetail] = useState(false);
  const remedy = onRemedy ? error.remedy : undefined;

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
                {showDetail
                  ? t("workspace_hide_technical_details")
                  : t("workspace_show_technical_details")}
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
  ws: Workspace;
  v: WorkspaceFlags;
  /** When absent, remedies render as message-only guidance. */
  onRemedy?: (action: RemedyAction) => void;
  fullHeight?: boolean;
  translationFooter?: React.ReactNode;
  resultCorner?: React.ReactNode;
  showTranslation?: boolean;
  onLookupSigner?: (keyId: string) => void;
}

export function WorkspaceResults({
  ws,
  v,
  onRemedy,
  fullHeight,
  translationFooter,
  resultCorner,
  showTranslation,
  onLookupSigner,
}: WorkspaceResultsProps) {
  const { result, output } = ws.state;
  const { error, hasOutputText: hasOutput, done: operationDone } = v;
  const verdict = result.verdict;
  const verifiedSigner = verdict?.signer ?? null;
  const statusText = result.status ?? undefined;
  const binaryOutput = result.binary;
  const fileResults = result.files;
  const { getOutput } = ws;
  const { contacts } = useContacts();
  const { keys: myKeys } = useKeyring();
  // The same state Reply hands its reader tab (see `SignerCard`).
  const card = verifiedSigner
    ? signerCardState({
        signer: verifiedSigner,
        tone: verdict?.tone ?? "success",
        note: verdict?.note,
        caveat: verdict?.caveat ?? null,
        statusText,
        // A machine translation is not what was signed.
        extraNote: showTranslation
          ? t("workspace_signature_covers_original")
          : null,
        contacts,
        myKeys,
      })
    : null;
  const isUnverified = !!card?.unverified;

  const hasContent =
    !!error ||
    !!verifiedSigner ||
    hasOutput ||
    !!binaryOutput ||
    fileResults.length > 0;
  if (!fullHeight && !hasContent) return null;

  // Over a readable message the signer band is the top block of its card;
  // elsewhere it stands alone.
  const signerInCard = !!fullHeight && hasOutput;
  const signerCard =
    verifiedSigner && card ? (
      <div
        className={signerInCard ? "shrink-0 [&>div]:rounded-[3px]" : undefined}
      >
        <SignerCard
          state={card}
          // Only for a key we hold: an unknown signer is a bare key id.
          labelAction={
            isUnverified ? undefined : (
              <KeyDetailsButton keyData={verifiedSigner} subtle />
            )
          }
          noteAction={
            isUnverified && onLookupSigner && verifiedSigner.keyId ? (
              <Button
                variant="outline"
                size="sm"
                onClick={() => onLookupSigner(verifiedSigner.keyId)}
              >
                <SearchIcon />
                {t("workspace_lookup_signer", { host: KEYSERVER_HOST })}
              </Button>
            ) : undefined
          }
        />
      </div>
    ) : null;

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

      {verifiedSigner && !signerInCard && signerCard}

      <OutputArea
        outputElRef={ws.outputElRef}
        getOutput={getOutput}
        hasOutput={hasOutput}
        binaryOutput={binaryOutput}
        fileResults={fileResults}
        fileName={ws.outputName()}
        success={operationDone}
        statusText={verifiedSigner ? undefined : statusText}
        fullHeight={fullHeight}
        showTranslation={showTranslation}
        translationElRef={ws.translationElRef}
        getTranslation={ws.getTranslation}
        footer={translationFooter}
        corner={resultCorner}
        header={signerInCard ? signerCard : undefined}
      />

      {output.publicKey && (
        <DetectedKeyBanner
          getText={getOutput}
          version={output.version}
          source="message"
        />
      )}
    </div>
  );
}
