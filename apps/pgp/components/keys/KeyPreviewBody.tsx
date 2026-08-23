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

import type { ComponentKeyRow, KeyFacts, KeyHealth } from "./key-facts";
import { useCopyToClipboard } from "../../hooks/useCopyToClipboard";
import { formatAlgorithm } from "../../lib/utils/formatting";

/**
 * The read-only body of a key: identity header, health banner, the facts
 * card (fingerprint, algorithm, dates) and the subkey list.
 *
 * Deliberately presentational -- it takes already-derived `KeyFacts`
 * (see ./key-facts) rather than armor or any one engine's parse result,
 * and knows nothing about storage. That's what lets the SAME component
 * render a stored key (KeyDetailsPage) and a key that has not been
 * imported yet (the import preview): the preview is the details page, so
 * the two can't drift apart -- and what lets a non-OpenPGP key, which has
 * no user IDs, dates or subkeys, render here as the smaller set of facts
 * it actually has instead of as a half-empty certificate.
 */

const EXPIRING_SOON_MS = 30 * 24 * 60 * 60 * 1000;

const STATUS_STYLES: Record<ComponentKeyRow["status"], string> = {
  active: "border-green-500/40 bg-green-500/10 text-green-400",
  expired: "border-amber-500/40 bg-amber-500/10 text-amber-400",
  revoked: "border-red-500/40 bg-red-500/10 text-red-400",
  invalid: "border-red-500/40 bg-red-500/10 text-red-400",
};

/** What this component key is used for, in plain words. */
function capabilityText(row: ComponentKeyRow): string {
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
  health: KeyHealth,
  expiresAt: number | null,
  primaryRow: ComponentKeyRow | null,
  isOwn: boolean,
): Banner | null {
  const now = Date.now();

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

  if (!health.usableForEncryption && !health.usableForSigning) {
    return {
      tone: "bad",
      title: "This key can't be used",
      lines: [
        health.policyError ?? "It has no usable encryption or signing subkey.",
      ],
    };
  }

  // A healthy key shows no banner at all -- silence means fine. Only
  // limitations and problems earn screen space.
  if (health.usableForEncryption && !health.usableForSigning) {
    return {
      tone: "warn",
      title: isOwn
        ? "You can receive encrypted messages, but this key can't sign."
        : "You can encrypt to it, but it can't sign.",
      lines: [],
    };
  }
  if (!health.usableForEncryption && health.usableForSigning) {
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

/** A fingerprint that is nothing but hex digits -- an OpenPGP one. The
 *  shape, not the prefix: an OpenSSH fingerprint happens to start
 *  `SHA256:`, but testing for that literal would mangle the next non-hex
 *  format just as badly, and this predicate keeps working without being
 *  told about it. */
const HEX_FINGERPRINT = /^[0-9a-fA-F]+$/;

/**
 * Fingerprint as aligned rows of five 4-char groups (the way GnuPG
 * prints it), so two fingerprints can be compared block by block.
 *
 * ONLY for a hex fingerprint. An OpenSSH one is `SHA256:` followed by
 * unpadded base64, where the grouping is not a convention but damage:
 * it split the prefix itself (`SHA2 56:I oCz+ ...`) and chopped the
 * base64 at offsets that mean nothing. That reached the clipboard too
 * (see `handleCopyFingerprint`), and comparing a fingerprint out of band
 * is the ONLY check a user has that GitHub served the key its owner
 * published -- `T-GITHUB-KEY-SUBSTITUTION` in
 * `lib/security/threat-model.ts`. A mangled copy defeats that silently:
 * it neither matches nor visibly fails.
 *
 * So a non-hex fingerprint is returned as ONE unbroken line -- rendered
 * whole, and copied byte-for-byte as `ssh-keygen -lf` prints it.
 */
export function fingerprintLines(fp: string): string[] {
  if (!HEX_FINGERPRINT.test(fp)) return [fp];
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

function SubkeyRow({
  row,
  label = "Subkey",
  action,
}: {
  row: ComponentKeyRow;
  label?: string;
  /** Optional trailing control for this row, supplied by the page (the
   *  details page's include/exclude toggle). Absent -- as it is in the
   *  import preview -- renders nothing, so the two screens keep sharing
   *  one component instead of forking. */
  action?: React.ReactNode;
}) {
  const caps = capabilityText(row);
  // An engine whose keys carry no dates (SSH) supplies neither, and the
  // whole clause is dropped rather than printed as the epoch.
  const dates =
    row.createdAt === undefined && row.expiresAt === undefined
      ? ""
      : `${row.createdAt !== undefined ? ` \u00b7 created ${format(new Date(row.createdAt), "PP")}` : ""}${
          row.expiresAt
            ? ` \u00b7 ${row.status === "expired" ? "expired" : "expires"} ${format(new Date(row.expiresAt), "PP")}`
            : row.expiresAt === null
              ? " \u00b7 never expires"
              : ""
        }`;
  return (
    <div className="border-border rounded-md border p-2.5">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-xs font-medium">{label}</span>
        {row.status !== "active" && (
          <span
            className={`rounded-full border px-1.5 py-px text-[10px] font-medium ${STATUS_STYLES[row.status]}`}
          >
            {row.status}
          </span>
        )}
        {action && <span className="ml-auto">{action}</span>}
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
        {row.bits ? ` (${row.bits}-bit)` : ""}
        {dates}
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
  /** What this key is, in the terms the body renders (see ./key-facts).
   *  `null` means there is nothing to show -- a cert that failed to parse,
   *  or an engine whose keys carry no metadata until they're imported --
   *  and every fact-driven section is simply left out. */
  facts: KeyFacts | null;
  /** True while the facts are still being fetched. Explicit rather than
   *  inferred from `facts === null`: "still loading" and "this key has no
   *  facts to show" are different screens, and conflating them left a
   *  metadata-less key saying "Loading…" forever. */
  loading?: boolean;
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
  /** Per-row control rendered in each component-key row's header. The
   *  import preview doesn't pass it; the details page uses it to hang an
   *  include/exclude toggle off each of a contact's keys. */
  rowAction?: (row: ComponentKeyRow) => React.ReactNode;
}

export function KeyPreviewBody({
  name,
  subtitle,
  email,
  akaEmails = [],
  chips = [],
  facts,
  loading = false,
  error,
  isOwn = false,
  securityWarning,
  addedAt,
  lastUsedAt,
  statusStrip,
  children,
  rowAction,
}: KeyPreviewBodyProps) {
  const [showInactive, setShowInactive] = useState(false);
  const [copiedFp, setCopiedFp] = useState(false);
  const copyTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const { copy } = useCopyToClipboard();

  useEffect(() => {
    return () => clearTimeout(copyTimer.current);
  }, []);

  const rows = facts?.components?.rows ?? null;
  const primaryRow = rows?.find((r) => r.isPrimary) ?? null;
  const subkeys = rows?.filter((r) => !r.isPrimary) ?? [];
  const activeSubkeys = subkeys.filter((r) => r.status === "active");
  const inactiveSubkeys = subkeys.filter((r) => r.status !== "active");
  const inactiveWord = inactiveSubkeys.every((r) => r.status === "expired")
    ? "expired"
    : inactiveSubkeys.every((r) => r.status === "revoked")
      ? "revoked"
      : "unusable";

  // Captured once at mount; the page is short-lived so drift is moot.
  const [now] = useState(() => Date.now());
  const expiresAt = facts?.expiresAt ?? null;
  const banner = facts?.health
    ? deriveBanner(facts.health, expiresAt, primaryRow, isOwn)
    : null;
  const keyExpired = expiresAt !== null && expiresAt < now;
  const keyExpiringSoon =
    expiresAt !== null && !keyExpired && expiresAt - now < EXPIRING_SOON_MS;

  const handleCopyFingerprint = (fp: string) => {
    // Joins the DISPLAYED lines, so what lands on the clipboard is what
    // is on screen. That is exactly why `fingerprintLines` must return a
    // non-hex fingerprint as a single line: this join would otherwise
    // put spaces inside an OpenSSH `SHA256:...` hash and quietly break
    // the out-of-band comparison it exists for.
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
      {!error && loading && (
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

      {facts && (
        <div className="border-border divide-border divide-y rounded-md border">
          {facts.fingerprint !== undefined && (
            <InfoRow label="Fingerprint">
              <span className="flex items-start gap-1.5">
                <span className="font-mono text-[11px] leading-relaxed">
                  {fingerprintLines(facts.fingerprint).map((line) => (
                    <span key={line} className="block">
                      {line}
                    </span>
                  ))}
                </span>
                <button
                  type="button"
                  onClick={() => handleCopyFingerprint(facts.fingerprint ?? "")}
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
          )}
          <InfoRow label="Algorithm">
            {formatAlgorithm(facts.algorithm)}
            {primaryRow?.bits ? ` · ${primaryRow.bits}-bit` : ""}
          </InfoRow>
          {primaryRow && capabilityText(primaryRow) && (
            <InfoRow label="Used for">{capabilityText(primaryRow)}</InfoRow>
          )}
          {facts.createdAt !== undefined && (
            <InfoRow label="Created">
              {format(new Date(facts.createdAt), "PPP")}
            </InfoRow>
          )}
          {facts.expiresAt !== undefined && (
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
          )}
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

      {facts?.components && (
        <div>
          <h3 className="mb-2 text-xs font-semibold">
            {facts.components.title ?? "Subkeys"}{" "}
            <span className="text-muted-foreground font-normal">
              ({subkeys.length})
            </span>
          </h3>
          {facts.components.truncated && (
            <p className="mb-2 text-xs text-amber-400">
              This certificate has an unusually large number of subkeys; only
              the first {facts.components.rows.length} are shown.
            </p>
          )}
          {subkeys.length === 0 && (
            <p className="text-muted-foreground text-xs">
              This key has no subkeys; the primary key does everything itself.
            </p>
          )}
          <div className="space-y-2">
            {activeSubkeys.map((row) => (
              <SubkeyRow
                key={row.fingerprint}
                row={row}
                label={facts.components?.rowLabel}
                action={rowAction?.(row)}
              />
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
                    <SubkeyRow
                      key={row.fingerprint}
                      row={row}
                      label={facts.components?.rowLabel}
                      action={rowAction?.(row)}
                    />
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
