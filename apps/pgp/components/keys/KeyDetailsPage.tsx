import { useEffect, useState } from "react";
import {
  CopyIcon,
  LockIcon,
  PencilIcon,
  StarIcon,
  StarOffIcon,
  Trash2Icon,
} from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import type { KeyDetails, KeyInfo } from "../../lib/pgp/types";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { KeyPreviewChip } from "./KeyPreviewBody";
import { useCopyToClipboard } from "../../hooks/useCopyToClipboard";
import { parseKey, parseKeyDetails } from "../../lib/pgp/wasm";
import { toast } from "../../lib/toast";
import { downloadText } from "../../lib/utils/download";
import { errorMessage } from "../../lib/utils/errors";
import { parseUserId } from "../../lib/utils/key-naming";
import {
  SlideOverHeader,
  SlideOverPanel,
  useSlideOver,
} from "../shared/SlideOver";
import { KeyPreviewBody } from "./KeyPreviewBody";

export type KeyDetailsTarget =
  | { kind: "own"; keyBlob: ProtectedKeyBlob }
  | { kind: "contact"; contact: PublicContactKey };

interface KeyDetailsPageProps {
  target: KeyDetailsTarget;
  onBack: () => void;
  /** Contacts only: jump to the workspace with this key preselected. */
  onEncryptTo?: () => void;
  /** Own keys only: open the rename page for this key. */
  onRename?: () => void;
  /** True when this is the user's configured default key. */
  isDefault?: boolean;
  /** Own keys only: set (true) or clear (false) this key as the
   *  default used for signing, decrypting, and encrypt-to-self. */
  onSetDefault?: (next: boolean) => void;
  /** Open the delete/remove confirmation page for this key. */
  onDelete?: () => void;
  /** Own keys only: mint (and persist) a revocation certificate for a
   *  key imported without one. Should throw with a user-readable message
   *  when the key is locked. */
  onGenerateRevocation?: () => Promise<string>;
}

/** Header icon button with a small hover label underneath (the UI kit
 *  has no tooltip primitive; a peer-hover span keeps it dependency-free). */
function IconAction({
  label,
  onClick,
  children,
}: {
  label: string;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <span className="relative">
      <button
        type="button"
        onClick={onClick}
        aria-label={label}
        className="peer text-muted-foreground hover:text-foreground rounded p-1 transition-colors"
      >
        {children}
      </button>
      <span className="border-border bg-background text-foreground pointer-events-none absolute top-full right-0 z-10 mt-1 hidden rounded border px-1.5 py-0.5 text-[10px] whitespace-nowrap shadow-sm peer-hover:block">
        {label}
      </span>
    </span>
  );
}

// ── revocation certificate (own keys) ────────────────────────────────

/** The stored revocation certificate for one of the user's own keys --
 *  generated keys carry one from creation; imported keys can mint one
 *  here on demand (requires the key to be unlocked). */
function RevocationSection({
  keyId,
  initialCertificate,
  onGenerate,
}: {
  keyId: string;
  initialCertificate?: string;
  onGenerate?: () => Promise<string>;
}) {
  const [certificate, setCertificate] = useState(initialCertificate ?? null);
  const [generating, setGenerating] = useState(false);
  const [genError, setGenError] = useState<string | null>(null);

  const handleDownload = () => {
    if (!certificate) return;
    downloadText(certificate, `revocation-${keyId.slice(-16)}.asc`);
  };

  const { copy } = useCopyToClipboard();
  const handleCopy = () => {
    if (!certificate) return;
    // A revocation cert is an irreversible instrument (anyone holding it
    // can revoke the key), so it gets the same clipboard hygiene as an
    // exported private key (sensitive = pref-driven wipe).
    void copy(certificate, {
      sensitive: true,
      label: "Revocation certificate",
    });
  };

  const handleGenerate = async () => {
    if (!onGenerate) return;
    setGenerating(true);
    setGenError(null);
    try {
      setCertificate(await onGenerate());
      toast.success("Revocation certificate created", {
        id: "revocation-created",
      });
    } catch (e) {
      setGenError(
        errorMessage(e, "Could not create a revocation certificate."),
      );
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div>
      <h3 className="mb-2 text-xs font-semibold">Revocation certificate</h3>
      <div className="border-border space-y-2 rounded-md border p-2.5">
        <p className="text-muted-foreground text-xs">
          {certificate
            ? "If this key is ever lost or compromised, publishing this " +
              "certificate tells your contacts to stop using the key. Back " +
              "it up somewhere safe - anyone who holds it can revoke your key."
            : "This key was imported without a revocation certificate. " +
              "Create one now and back it up, so you can revoke the key " +
              "later even if you lose access to it."}
        </p>
        {certificate ? (
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={handleDownload}>
              Download
            </Button>
            <Button variant="outline" size="sm" onClick={handleCopy}>
              Copy
            </Button>
          </div>
        ) : (
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void handleGenerate()}
              disabled={generating || !onGenerate}
            >
              {generating ? "Creating..." : "Create revocation certificate"}
            </Button>
            {genError && (
              <p className="text-destructive text-xs" role="alert">
                {genError}
              </p>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ── page ─────────────────────────────────────────────────────────────

export function KeyDetailsPage({
  target,
  onBack,
  onEncryptTo,
  onRename,
  isDefault,
  onSetDefault,
  onDelete,
  onGenerateRevocation,
}: KeyDetailsPageProps) {
  const { entered, close } = useSlideOver(onBack);
  const [info, setInfo] = useState<KeyInfo | null>(null);
  const [details, setDetails] = useState<KeyDetails | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { copy } = useCopyToClipboard();

  const isOwn = target.kind === "own";
  const armored = isOwn
    ? target.keyBlob.publicKeyArmored
    : target.contact.armoredPublicKey;
  const userIds = isOwn ? target.keyBlob.userIds : target.contact.userIds;
  const securityWarning = isOwn
    ? target.keyBlob.securityWarning
    : target.contact.securityWarning;
  const lastUsedAt = isOwn
    ? target.keyBlob.lastUsedAt
    : target.contact.lastUsedAt;
  const addedAt = isOwn ? target.keyBlob.createdAt : target.contact.addedAt;

  const primaryUserId = userIds[0] ?? "Unknown";
  const { name: rawName, email, comment } = parseUserId(primaryUserId);
  const realName = comment ? `${rawName} (${comment})` : rawName;
  // Local alias wins as the headline; the real identity moves to a
  // subtitle so it's never hidden.
  const alias = isOwn ? target.keyBlob.alias : undefined;
  const name = alias ?? realName;

  // Other identities on the cert, shown as deduped emails so we don't
  // repeat the display name three times.
  const akaEmails = Array.from(
    new Set(
      userIds
        .slice(1)
        .map((uid) => parseUserId(uid).email || uid)
        .filter((e) => e !== email),
    ),
  );

  const chips: KeyPreviewChip[] = [];
  if (isDefault) {
    chips.push({
      label: "Default",
      title: "Used by default for signing, decrypting, and encrypt-to-self",
    });
  }
  chips.push({
    label: isOwn ? "Your key" : "Contact",
    title: isOwn ? "You hold the private key" : "You hold their public key",
  });
  if (isOwn) {
    chips.push({
      label:
        target.keyBlob.protection.method === "passkey" ? "Passkey" : "Password",
      title: "How the private key is protected at rest",
    });
  }

  useEffect(() => {
    let cancelled = false;
    Promise.all([parseKey(armored), parseKeyDetails(armored)])
      .then(([keyInfo, keyDetails]) => {
        if (cancelled) return;
        setInfo(keyInfo);
        setDetails(keyDetails);
      })
      .catch(() => {
        if (!cancelled) setError("Could not parse this key.");
      });
    return () => {
      cancelled = true;
    };
  }, [armored]);

  const handleCopyPublicKey = () => {
    void copy(armored, { label: "Public key" });
  };

  return (
    <SlideOverPanel entered={entered} ariaLabel={`Key details for ${name}`}>
      <SlideOverHeader title="Key details" onBack={close}>
        {onEncryptTo && (
          <IconAction label="Encrypt to" onClick={onEncryptTo}>
            <LockIcon className="h-4 w-4" />
          </IconAction>
        )}
        {onRename && (
          <IconAction label="Rename" onClick={onRename}>
            <PencilIcon className="h-4 w-4" />
          </IconAction>
        )}
        {onSetDefault && (
          <IconAction
            label={isDefault ? "Remove default" : "Set as default key"}
            onClick={() => {
              onSetDefault(!isDefault);
              toast.success(
                isDefault ? "Default key removed" : "Default key set",
                { id: "default-key-toggled" },
              );
            }}
          >
            {isDefault ? (
              <StarOffIcon className="h-4 w-4" />
            ) : (
              <StarIcon className="h-4 w-4" />
            )}
          </IconAction>
        )}
        <IconAction label="Copy public key" onClick={handleCopyPublicKey}>
          <CopyIcon className="h-4 w-4" />
        </IconAction>
        {onDelete && (
          <IconAction
            label={isOwn ? "Delete key" : "Remove contact"}
            onClick={onDelete}
          >
            <Trash2Icon className="h-4 w-4" />
          </IconAction>
        )}
      </SlideOverHeader>

      <div className="flex-1 space-y-4 overflow-y-auto p-3">
        <KeyPreviewBody
          name={name}
          subtitle={alias ? realName : undefined}
          email={email}
          akaEmails={akaEmails}
          chips={chips}
          info={info}
          details={details}
          error={error}
          isOwn={isOwn}
          securityWarning={securityWarning}
          addedAt={addedAt}
          lastUsedAt={isOwn ? lastUsedAt : undefined}
        >
          {isOwn && (
            <RevocationSection
              keyId={target.keyBlob.keyId}
              initialCertificate={target.keyBlob.revocationCertificate}
              onGenerate={onGenerateRevocation}
            />
          )}
        </KeyPreviewBody>
      </div>
    </SlideOverPanel>
  );
}
