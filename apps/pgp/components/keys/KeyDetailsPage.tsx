import { useCallback, useEffect, useRef, useState } from "react";
import { format, formatDistanceToNow } from "date-fns";
import {
  ArrowLeftIcon,
  CheckCircleIcon,
  CheckIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  CopyIcon,
  LockIcon,
  Trash2Icon,
  TriangleAlertIcon,
  XCircleIcon,
} from "lucide-react";
import { toast } from "sonner";

import type { KeyDetails, KeyInfo, SubkeyDetail } from "../../lib/pgp/types";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import { parseKey, parseKeyDetails } from "../../lib/pgp/wasm";
import { formatAlgorithm } from "../../lib/utils/formatting";
import { parseUserId } from "../../lib/utils/key-naming";

export type KeyDetailsTarget =
  | { kind: "own"; keyBlob: ProtectedKeyBlob }
  | { kind: "contact"; contact: PublicContactKey };

interface KeyDetailsPageProps {
  target: KeyDetailsTarget;
  onBack: () => void;
  /** Contacts only: jump to the workspace with this key preselected. */
  onEncryptTo?: () => void;
  /** Delete the key / remove the contact. The page closes afterwards. */
  onDelete?: () => void | Promise<void>;
}

/** Header icon button with a small hover label underneath (the UI kit
 *  has no tooltip primitive; a peer-hover span keeps it dependency-free). */
function IconAction({
  label,
  onClick,
  destructive,
  forceLabel,
  children,
}: {
  label: string;
  onClick: () => void;
  destructive?: boolean;
  /** Keep the label visible without hover (e.g. armed delete). */
  forceLabel?: boolean;
  children: React.ReactNode;
}) {
  return (
    <span className="relative">
      <button
        type="button"
        onClick={onClick}
        aria-label={label}
        className={`peer rounded p-1 transition-colors ${
          destructive
            ? "text-destructive"
            : "text-muted-foreground hover:text-foreground"
        }`}
      >
        {children}
      </button>
      <span
        className={`border-border bg-background text-foreground pointer-events-none absolute top-full right-0 z-10 mt-1 rounded border px-1.5 py-0.5 text-[10px] whitespace-nowrap shadow-sm peer-hover:block ${
          forceLabel ? "block" : "hidden"
        }`}
      >
        {label}
      </span>
    </span>
  );
}

/** Must match the `duration-300` class on the panel. */
const SLIDE_MS = 300;

const EXPIRING_SOON_MS = 30 * 24 * 60 * 60 * 1000;

const STATUS_STYLES: Record<SubkeyDetail["status"], string> = {
  active:
    "border-green-500/40 bg-green-500/10 text-green-600 dark:text-green-400",
  expired:
    "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400",
  revoked: "border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400",
  invalid: "border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400",
};

/** What this component key is used for, in plain words. */
function capabilityText(row: SubkeyDetail): string {
  const parts: string[] = [];
  if (row.canSign) parts.push("Signs messages");
  if (row.canEncrypt) parts.push("Receives encrypted messages");
  if (row.canAuthenticate) parts.push("Authenticates (e.g. SSH)");
  if (row.canCertify) parts.push("Vouches for identities");
  return parts.join(" · ");
}

// ── status banner ────────────────────────────────────────────────────
// The one question users bring to this page is "is this key okay to
// use, and until when?" -- answer it up top, in words, before the data.

interface Banner {
  tone: "ok" | "warn" | "bad";
  title: string;
  lines: string[];
}

function deriveBanner(
  info: KeyInfo,
  primaryRow: SubkeyDetail | null,
  isOwn: boolean,
): Banner {
  const now = Date.now();
  const expiresAt = info.expiresAt;

  if (primaryRow?.status === "revoked") {
    return {
      tone: "bad",
      title: "This key has been revoked",
      lines: [
        primaryRow.revocationReason ?? "No reason was given.",
        isOwn
          ? "Generate or import a replacement key."
          : "Do not encrypt to it or trust new signatures from it.",
      ],
    };
  }

  if (expiresAt !== null && expiresAt < now) {
    return {
      tone: "bad",
      title: `This key expired ${formatDistanceToNow(expiresAt, { addSuffix: true })}`,
      lines: [
        `It stopped being valid on ${format(expiresAt, "PPP")}.`,
        isOwn
          ? "Generate or import a newer key."
          : "Ask the owner for an updated key.",
      ],
    };
  }

  if (!info.usableForEncryption && !info.usableForSigning) {
    return {
      tone: "bad",
      title: "This key can't be used",
      lines: [
        info.policyError ?? "It has no usable encryption or signing subkey.",
      ],
    };
  }

  const lines: string[] = [];
  if (info.usableForEncryption && info.usableForSigning) {
    lines.push(
      isOwn
        ? "You can sign messages and receive encrypted ones."
        : "You can encrypt to it and verify its signatures.",
    );
  } else if (info.usableForEncryption) {
    lines.push(
      isOwn
        ? "You can receive encrypted messages, but this key can't sign."
        : "You can encrypt to it, but it can't sign.",
    );
  } else {
    lines.push(
      isOwn
        ? "You can sign messages, but this key can't receive encrypted ones."
        : "You can verify its signatures, but can't encrypt to it.",
    );
  }

  const expiringSoon = expiresAt !== null && expiresAt - now < EXPIRING_SOON_MS;
  if (expiresAt !== null) {
    lines.push(
      `Expires ${format(expiresAt, "PPP")} (${formatDistanceToNow(expiresAt, { addSuffix: true })}).`,
    );
  } else {
    lines.push("Never expires.");
  }

  const partial = !(info.usableForEncryption && info.usableForSigning);
  return {
    tone: partial || expiringSoon ? "warn" : "ok",
    title: expiringSoon
      ? "Good to use, but expiring soon"
      : isOwn
        ? "This key is ready to use"
        : "This key is good to use",
    lines,
  };
}

const BANNER_STYLES: Record<Banner["tone"], { box: string; title: string }> = {
  ok: {
    box: "border-green-500/40 bg-green-500/10",
    title: "text-green-600 dark:text-green-400",
  },
  warn: {
    box: "border-amber-500/40 bg-amber-500/10",
    title: "text-amber-700 dark:text-amber-400",
  },
  bad: {
    box: "border-red-500/40 bg-red-500/10",
    title: "text-red-600 dark:text-red-400",
  },
};

function StatusBanner({ banner }: { banner: Banner }) {
  const styles = BANNER_STYLES[banner.tone];
  const Icon =
    banner.tone === "ok"
      ? CheckCircleIcon
      : banner.tone === "warn"
        ? TriangleAlertIcon
        : XCircleIcon;
  return (
    <div className={`rounded-md border p-2.5 ${styles.box}`}>
      <p
        className={`flex items-center gap-1.5 text-xs font-medium ${styles.title}`}
      >
        <Icon className="h-3.5 w-3.5 shrink-0" />
        {banner.title}
      </p>
      <div className="mt-1 space-y-0.5 pl-5">
        {banner.lines.map((line) => (
          <p key={line} className="text-muted-foreground text-xs">
            {line}
          </p>
        ))}
      </div>
    </div>
  );
}

// ── building blocks ──────────────────────────────────────────────────

/** Fingerprint as aligned rows of five 4-char groups (the way GnuPG
 *  prints it), so two fingerprints can be compared block by block. */
function fingerprintLines(fp: string): string[] {
  const groups = fp.match(/.{1,4}/g) ?? [fp];
  const lines: string[] = [];
  for (let i = 0; i < groups.length; i += 5) {
    lines.push(groups.slice(i, i + 5).join(" "));
  }
  return lines;
}

function InfoRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex gap-3 text-xs">
      <span className="text-muted-foreground w-20 shrink-0">{label}</span>
      <span className="min-w-0 flex-1">{children}</span>
    </div>
  );
}

function SubkeyRow({ row }: { row: SubkeyDetail }) {
  const caps = capabilityText(row);
  return (
    <div className="border-border rounded-md border p-2.5">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-xs font-medium">Subkey</span>
        {row.status !== "active" && (
          <span
            className={`rounded-full border px-1.5 py-px text-[10px] font-medium ${STATUS_STYLES[row.status]}`}
          >
            {row.status}
          </span>
        )}
      </div>
      {caps && <p className="text-muted-foreground mt-0.5 text-xs">{caps}</p>}
      <p className="text-muted-foreground mt-1.5 font-mono text-[10px] leading-relaxed">
        {fingerprintLines(row.fingerprint).map((line) => (
          <span key={line} className="block">
            {line}
          </span>
        ))}
      </p>
      <p className="text-muted-foreground mt-0.5 text-[11px]">
        {formatAlgorithm(row.algorithm)}
        {row.bits ? ` (${row.bits}-bit)` : ""} · created{" "}
        {format(new Date(row.createdAt), "PP")}
        {row.expiresAt
          ? ` · ${row.status === "expired" ? "expired" : "expires"} ${format(new Date(row.expiresAt), "PP")}`
          : " · never expires"}
      </p>
      {row.revocationReason && (
        <p className="mt-1 text-[11px] text-red-600 dark:text-red-400">
          Revoked: {row.revocationReason}
        </p>
      )}
      {row.policyError && (
        <p className="mt-1 text-[11px] text-amber-700 dark:text-amber-400">
          {row.policyError}
        </p>
      )}
    </div>
  );
}

// ── page ─────────────────────────────────────────────────────────────

export function KeyDetailsPage({
  target,
  onBack,
  onEncryptTo,
  onDelete,
}: KeyDetailsPageProps) {
  const [entered, setEntered] = useState(false);
  const [info, setInfo] = useState<KeyInfo | null>(null);
  const [details, setDetails] = useState<KeyDetails | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showInactive, setShowInactive] = useState(false);
  const [copiedFp, setCopiedFp] = useState(false);
  const [deleteArmed, setDeleteArmed] = useState(false);
  const copyTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const deleteTimer = useRef<ReturnType<typeof setTimeout>>(undefined);

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
  const name = comment ? `${rawName} (${comment})` : rawName;

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

  // Slide in on mount; slide out, then unmount, on back.
  useEffect(() => {
    const raf = requestAnimationFrame(() => setEntered(true));
    return () => cancelAnimationFrame(raf);
  }, []);

  useEffect(() => {
    return () => {
      clearTimeout(copyTimer.current);
      clearTimeout(deleteTimer.current);
    };
  }, []);

  const handleBack = useCallback(() => {
    setEntered(false);
    setTimeout(onBack, SLIDE_MS);
  }, [onBack]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") handleBack();
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [handleBack]);

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

  const rows = details?.keys ?? null;
  const primaryRow = rows?.find((r) => r.isPrimary) ?? null;
  const subkeys = rows?.filter((r) => !r.isPrimary) ?? [];
  const activeSubkeys = subkeys.filter((r) => r.status === "active");
  const inactiveSubkeys = subkeys.filter((r) => r.status !== "active");
  const inactiveWord = inactiveSubkeys.every((r) => r.status === "expired")
    ? "expired"
    : inactiveSubkeys.every((r) => r.status === "revoked")
      ? "revoked"
      : "unusable";

  const banner = info ? deriveBanner(info, primaryRow, isOwn) : null;

  const handleCopyFingerprint = (fp: string) => {
    void navigator.clipboard.writeText(fingerprintLines(fp).join(" "));
    setCopiedFp(true);
    clearTimeout(copyTimer.current);
    copyTimer.current = setTimeout(() => setCopiedFp(false), 2000);
  };

  const handleCopyPublicKey = () => {
    void navigator.clipboard.writeText(armored);
    toast.success("Public key copied");
  };

  // Two-stage delete: first click arms (label flips to confirm),
  // second click within 3s executes and closes the page.
  const handleDelete = () => {
    if (!onDelete) return;
    if (!deleteArmed) {
      setDeleteArmed(true);
      clearTimeout(deleteTimer.current);
      deleteTimer.current = setTimeout(() => setDeleteArmed(false), 3000);
      return;
    }
    clearTimeout(deleteTimer.current);
    void onDelete();
    handleBack();
  };

  return (
    <div
      className={`bg-background fixed inset-0 z-50 flex flex-col transition-transform duration-300 ease-out ${entered ? "translate-x-0" : "translate-x-full"}`}
      role="region"
      aria-label={`Key details for ${name}`}
    >
      <div className="border-border flex items-center gap-2 border-b px-3 py-2.5">
        <button
          type="button"
          onClick={handleBack}
          aria-label="Back"
          className="text-muted-foreground hover:text-foreground rounded p-1 transition-colors"
        >
          <ArrowLeftIcon className="h-4 w-4" />
        </button>
        <h2 className="truncate text-sm font-semibold">Key details</h2>
        <span className="flex-1" />
        {onEncryptTo && (
          <IconAction label="Encrypt to" onClick={onEncryptTo}>
            <LockIcon className="h-4 w-4" />
          </IconAction>
        )}
        <IconAction label="Copy public key" onClick={handleCopyPublicKey}>
          <CopyIcon className="h-4 w-4" />
        </IconAction>
        {onDelete && (
          <IconAction
            label={
              deleteArmed
                ? "Click again to confirm"
                : isOwn
                  ? "Delete key"
                  : "Remove contact"
            }
            destructive={deleteArmed}
            forceLabel={deleteArmed}
            onClick={handleDelete}
          >
            <Trash2Icon className="h-4 w-4" />
          </IconAction>
        )}
      </div>

      <div className="flex-1 space-y-4 overflow-y-auto p-3">
        <div>
          <p className="text-sm font-medium">{name}</p>
          {email && <p className="text-muted-foreground text-xs">{email}</p>}
          <p className="text-muted-foreground mt-0.5 text-xs">
            {isOwn
              ? `Your key · ${target.keyBlob.protection.method === "passkey" ? "Passkey" : "Password"} protected`
              : "Contact · you hold their public key"}
          </p>
          {akaEmails.length > 0 && (
            <div className="mt-1.5">
              <p className="text-muted-foreground text-[10px] font-medium tracking-wide uppercase">
                Also known as
              </p>
              {akaEmails.map((aka) => (
                <p key={aka} className="text-muted-foreground text-xs">
                  {aka}
                </p>
              ))}
            </div>
          )}
        </div>

        {error && <p className="text-destructive text-xs">{error}</p>}
        {!error && info === null && (
          <p className="text-muted-foreground text-xs">Loading…</p>
        )}

        {banner && <StatusBanner banner={banner} />}

        {securityWarning && (
          <div className="flex items-start gap-1.5 rounded-md border border-amber-500/40 bg-amber-500/10 p-2">
            <TriangleAlertIcon className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-700 dark:text-amber-400" />
            <p className="text-xs text-amber-700 dark:text-amber-400">
              {securityWarning}
            </p>
          </div>
        )}

        {info && (
          <div className="space-y-1.5">
            <InfoRow label="Fingerprint">
              <span className="flex items-start gap-1.5">
                <span className="font-mono text-[11px] leading-relaxed">
                  {fingerprintLines(info.keyId).map((line) => (
                    <span key={line} className="block">
                      {line}
                    </span>
                  ))}
                </span>
                <button
                  type="button"
                  onClick={() => handleCopyFingerprint(info.keyId)}
                  aria-label="Copy fingerprint"
                  className="text-muted-foreground hover:text-foreground rounded p-0.5 transition-colors"
                >
                  {copiedFp ? (
                    <CheckIcon className="h-3 w-3 text-green-500" />
                  ) : (
                    <CopyIcon className="h-3 w-3" />
                  )}
                </button>
              </span>
            </InfoRow>
            <InfoRow label="Algorithm">
              {formatAlgorithm(info.algorithm)}
              {primaryRow?.bits ? ` · ${primaryRow.bits}-bit` : ""}
            </InfoRow>
            {primaryRow && capabilityText(primaryRow) && (
              <InfoRow label="Used for">{capabilityText(primaryRow)}</InfoRow>
            )}
            <InfoRow label="Created">
              {format(new Date(info.createdAt), "PPP")}
            </InfoRow>
            <InfoRow label="Added">{format(new Date(addedAt), "PPP")}</InfoRow>
            <InfoRow label="Last used">
              {format(new Date(lastUsedAt), "PPP")}
            </InfoRow>
          </div>
        )}

        {details && (
          <div>
            <h3 className="mb-2 text-xs font-semibold">
              Subkeys ({subkeys.length})
            </h3>
            {details.truncated && (
              <p className="mb-2 text-xs text-amber-700 dark:text-amber-400">
                This certificate has an unusually large number of subkeys; only
                the first {details.keys.length} are shown.
              </p>
            )}
            {subkeys.length === 0 && (
              <p className="text-muted-foreground text-xs">
                This key has no subkeys; the primary key does everything itself.
              </p>
            )}
            <div className="space-y-2">
              {activeSubkeys.map((row) => (
                <SubkeyRow key={row.fingerprint} row={row} />
              ))}
            </div>
            {inactiveSubkeys.length > 0 && (
              <div className="mt-2">
                <button
                  type="button"
                  onClick={() => setShowInactive((v) => !v)}
                  aria-expanded={showInactive}
                  className="text-muted-foreground hover:text-foreground flex items-center gap-1 py-1 text-xs transition-colors"
                >
                  {showInactive ? (
                    <ChevronDownIcon className="h-3.5 w-3.5" />
                  ) : (
                    <ChevronRightIcon className="h-3.5 w-3.5" />
                  )}
                  {inactiveSubkeys.length} {inactiveWord} subkey
                  {inactiveSubkeys.length === 1 ? "" : "s"}
                </button>
                {showInactive && (
                  <div className="mt-1 space-y-2">
                    {inactiveSubkeys.map((row) => (
                      <SubkeyRow key={row.fingerprint} row={row} />
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
