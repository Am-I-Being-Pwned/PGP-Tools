import { useEffect, useRef, useState } from "react";
import { format, formatDistanceToNow } from "date-fns";
import {
  CheckIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  CopyIcon,
  TriangleAlertIcon,
  XCircleIcon,
} from "lucide-react";

import type { KeyDetails, KeyInfo, SubkeyDetail } from "../../lib/pgp/types";
import { useCopyToClipboard } from "../../hooks/useCopyToClipboard";
import { formatAlgorithm } from "../../lib/utils/formatting";

/**
 * The read-only body of a key: identity header, health banner, the facts
 * card (fingerprint, algorithm, dates) and the subkey list.
 *
 * Deliberately presentational -- it takes already-parsed `KeyInfo` /
 * `KeyDetails` rather than armor, and knows nothing about storage. That's
 * what lets the SAME component render a stored key (KeyDetailsPage) and a
 * key that has not been imported yet (the import preview): the preview is
 * the details page, so the two can't drift apart.
 */

const EXPIRING_SOON_MS = 30 * 24 * 60 * 60 * 1000;

const STATUS_STYLES: Record<SubkeyDetail["status"], string> = {
  active: "border-green-500/40 bg-green-500/10 text-green-400",
  expired: "border-amber-500/40 bg-amber-500/10 text-amber-400",
  revoked: "border-red-500/40 bg-red-500/10 text-red-400",
  invalid: "border-red-500/40 bg-red-500/10 text-red-400",
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
  tone: "warn" | "bad";
  title: string;
  lines: string[];
}

function deriveBanner(
  info: KeyInfo,
  primaryRow: SubkeyDetail | null,
  isOwn: boolean,
): Banner | null {
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

  // A healthy key shows no banner at all -- silence means fine. Only
  // limitations and problems earn screen space.
  if (info.usableForEncryption && !info.usableForSigning) {
    return {
      tone: "warn",
      title: isOwn
        ? "You can receive encrypted messages, but this key can't sign."
        : "You can encrypt to it, but it can't sign.",
      lines: [],
    };
  }
  if (!info.usableForEncryption && info.usableForSigning) {
    return {
      tone: "warn",
      title: isOwn
        ? "You can sign messages, but this key can't receive encrypted ones."
        : "You can verify its signatures, but can't encrypt to it.",
      lines: [],
    };
  }

  if (expiresAt !== null && expiresAt - now < EXPIRING_SOON_MS) {
    return { tone: "warn", title: "This key expires soon", lines: [] };
  }

  return null;
}

const BANNER_STYLES: Record<Banner["tone"], { box: string; title: string }> = {
  warn: {
    box: "border-amber-500/40 bg-amber-500/10",
    title: "text-amber-400",
  },
  bad: {
    box: "border-red-500/40 bg-red-500/10",
    title: "text-red-400",
  },
};

function StatusBanner({ banner }: { banner: Banner }) {
  const styles = BANNER_STYLES[banner.tone];
  const Icon = banner.tone === "warn" ? TriangleAlertIcon : XCircleIcon;
  return (
    <div className={`rounded-md border p-2.5 ${styles.box}`}>
      <p
        className={`flex items-center gap-1.5 text-xs font-medium ${styles.title}`}
      >
        <Icon className="h-3.5 w-3.5 shrink-0" />
        {banner.title}
      </p>
      {banner.lines.length > 0 && (
        <div className="mt-1 space-y-0.5 pl-5">
          {banner.lines.map((line) => (
            <p key={line} className="text-muted-foreground text-xs">
              {line}
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

// ── building blocks ──────────────────────────────────────────────────

/** Fingerprint as aligned rows of five 4-char groups (the way GnuPG
 *  prints it), so two fingerprints can be compared block by block. */
export function fingerprintLines(fp: string): string[] {
  const groups = fp.match(/.{1,4}/g) ?? [fp];
  const lines: string[] = [];
  for (let i = 0; i < groups.length; i += 5) {
    lines.push(groups.slice(i, i + 5).join(" "));
  }
  return lines;
}

/** One row of the bordered facts card; parent supplies divide-y. */
function InfoRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex gap-3 px-3 py-2 text-xs">
      <span className="text-muted-foreground w-20 shrink-0">{label}</span>
      <span className="min-w-0 flex-1">{children}</span>
    </div>
  );
}

/** Small identity chip, e.g. "Contact" or "Passkey". */
export function Chip({
  title,
  children,
}: {
  title?: string;
  children: string;
}) {
  return (
    <span
      title={title}
      className="border-border text-muted-foreground rounded-full border px-2 py-0.5 text-[10px] font-medium whitespace-nowrap"
    >
      {children}
    </span>
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
        <p className="mt-1 text-[11px] text-red-400">
          Revoked: {row.revocationReason}
        </p>
      )}
      {row.policyError && (
        <p className="mt-1 text-[11px] text-amber-400">{row.policyError}</p>
      )}
    </div>
  );
}

// ── body ─────────────────────────────────────────────────────────────

export interface KeyPreviewChip {
  label: string;
  title?: string;
}

export interface KeyPreviewBodyProps {
  /** Headline identity (a local alias wins over the cert's own name). */
  name: string;
  /** The cert's real name, when an alias took the headline. */
  subtitle?: string;
  email?: string;
  /** Other identities on the cert, as deduped emails. */
  akaEmails?: string[];
  chips?: KeyPreviewChip[];
  /** Parsed cert facts. `null` renders the loading line. */
  info: KeyInfo | null;
  details: KeyDetails | null;
  error?: string | null;
  /** Wording of the health banner ("you can sign" vs "it can sign"). */
  isOwn?: boolean;
  securityWarning?: string;
  /** Stored keys only -- a key being previewed for import has neither. */
  addedAt?: number;
  lastUsedAt?: number;
  /** Rendered above the health banner: the import flow's new/update/
   *  already-imported strip. */
  statusStrip?: React.ReactNode;
  /** Trailing sections (e.g. the revocation certificate card). */
  children?: React.ReactNode;
}

export function KeyPreviewBody({
  name,
  subtitle,
  email,
  akaEmails = [],
  chips = [],
  info,
  details,
  error,
  isOwn = false,
  securityWarning,
  addedAt,
  lastUsedAt,
  statusStrip,
  children,
}: KeyPreviewBodyProps) {
  const [showInactive, setShowInactive] = useState(false);
  const [copiedFp, setCopiedFp] = useState(false);
  const copyTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const { copy } = useCopyToClipboard();

  useEffect(() => {
    return () => clearTimeout(copyTimer.current);
  }, []);

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

  // Captured once at mount; the page is short-lived so drift is moot.
  const [now] = useState(() => Date.now());
  const expiresAt = info?.expiresAt ?? null;
  const keyExpired = expiresAt !== null && expiresAt < now;
  const keyExpiringSoon =
    expiresAt !== null && !keyExpired && expiresAt - now < EXPIRING_SOON_MS;

  const handleCopyFingerprint = (fp: string) => {
    // No label: the inline 2s check is the success feedback.
    void copy(fingerprintLines(fp).join(" ")).then((ok) => {
      if (!ok) return;
      setCopiedFp(true);
      clearTimeout(copyTimer.current);
      copyTimer.current = setTimeout(() => setCopiedFp(false), 2000);
    });
  };

  return (
    <>
      <div>
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <p className="truncate text-base leading-tight font-semibold">
              {name}
            </p>
            {subtitle && (
              <p className="text-muted-foreground mt-0.5 truncate text-xs">
                {subtitle}
              </p>
            )}
            {email && (
              <p className="text-muted-foreground mt-0.5 truncate text-xs">
                {email}
              </p>
            )}
          </div>
          {chips.length > 0 && (
            <div className="flex shrink-0 gap-1 pt-0.5">
              {chips.map((chip) => (
                <Chip key={chip.label} title={chip.title}>
                  {chip.label}
                </Chip>
              ))}
            </div>
          )}
        </div>
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

      {statusStrip}

      {error && <p className="text-destructive text-xs">{error}</p>}
      {!error && info === null && (
        <p className="text-muted-foreground text-xs">Loading…</p>
      )}

      {banner && <StatusBanner banner={banner} />}

      {securityWarning && (
        <div className="flex items-start gap-1.5 border-l-2 border-amber-500/60 py-0.5 pl-2.5">
          <TriangleAlertIcon className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-400" />
          <p className="text-xs leading-relaxed text-amber-400">
            {securityWarning}
          </p>
        </div>
      )}

      {info && (
        <div className="border-border divide-border divide-y rounded-md border">
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
          <InfoRow label="Expires">
            {expiresAt === null ? (
              "Never"
            ) : (
              <span
                className={
                  keyExpired
                    ? "text-red-400"
                    : keyExpiringSoon
                      ? "text-amber-400"
                      : undefined
                }
              >
                {format(new Date(expiresAt), "PPP")} (
                {formatDistanceToNow(new Date(expiresAt), {
                  addSuffix: true,
                })}
                )
              </span>
            )}
          </InfoRow>
          {addedAt !== undefined && (
            <InfoRow label="Added">{format(new Date(addedAt), "PPP")}</InfoRow>
          )}
          {/* Only own keys track this (bumped on unlock); a contact's
              lastUsedAt is frozen at import time, so showing it would
              just repeat "Added". */}
          {lastUsedAt !== undefined && (
            <InfoRow label="Last used">
              {format(new Date(lastUsedAt), "PPP")}
            </InfoRow>
          )}
        </div>
      )}

      {details && (
        <div>
          <h3 className="mb-2 text-xs font-semibold">
            Subkeys{" "}
            <span className="text-muted-foreground font-normal">
              ({subkeys.length})
            </span>
          </h3>
          {details.truncated && (
            <p className="mb-2 text-xs text-amber-400">
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

      {children}
    </>
  );
}
