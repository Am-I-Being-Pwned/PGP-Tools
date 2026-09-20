import { useEffect, useRef, useState } from "react";
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
import { t, tn } from "../../lib/i18n";
import {
  formatDate,
  formatDateShort,
  formatRelative,
} from "../../lib/i18n/format";
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

/** Lowercase status word for the pill; resolved at render time. */
function statusText(status: ComponentKeyRow["status"]): string {
  switch (status) {
    case "expired":
      return t("keys_status_expired");
    case "revoked":
      return t("keys_status_revoked");
    case "invalid":
      return t("keys_status_invalid");
    case "active":
      return status;
  }
}

const STATUS_STYLES: Record<ComponentKeyRow["status"], string> = {
  active: "border-green-500/40 bg-green-500/10 text-green-400",
  expired: "border-amber-500/40 bg-amber-500/10 text-amber-400",
  revoked: "border-red-500/40 bg-red-500/10 text-red-400",
  invalid: "border-red-500/40 bg-red-500/10 text-red-400",
};

/** What this component key is used for, in plain words. */
function capabilityText(row: ComponentKeyRow): string {
  const parts: string[] = [];
  if (row.canSign) parts.push(t("keys_cap_sign"));
  if (row.canEncrypt) parts.push(t("keys_cap_encrypt"));
  if (row.canAuthenticate) parts.push(t("keys_cap_auth"));
  if (row.canCertify) parts.push(t("keys_cap_certify"));
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
      title: t("keys_banner_revoked_title"),
      lines: [
        primaryRow.revocationReason ?? t("keys_banner_no_reason"),
        isOwn ? t("keys_banner_revoked_own") : t("keys_banner_revoked_contact"),
      ],
    };
  }

  if (expiresAt !== null && expiresAt < now) {
    return {
      tone: "bad",
      title: t("keys_banner_expired_title", {
        when: formatRelative(expiresAt),
      }),
      lines: [
        t("keys_banner_expired_on", { date: formatDate(expiresAt) }),
        isOwn ? t("keys_banner_expired_own") : t("keys_banner_expired_contact"),
      ],
    };
  }

  if (!health.usableForEncryption && !health.usableForSigning) {
    return {
      tone: "bad",
      title: t("keys_banner_unusable_title"),
      lines: [health.policyError ?? t("keys_banner_unusable_body")],
    };
  }

  // A healthy key shows no banner at all -- silence means fine. Only
  // limitations and problems earn screen space.
  if (health.usableForEncryption && !health.usableForSigning) {
    return {
      tone: "warn",
      title: isOwn
        ? t("keys_banner_encrypt_only_own")
        : t("keys_banner_encrypt_only_contact"),
      lines: [],
    };
  }
  if (!health.usableForEncryption && health.usableForSigning) {
    return {
      tone: "warn",
      title: isOwn
        ? t("keys_banner_sign_only_own")
        : t("keys_banner_sign_only_contact"),
      lines: [],
    };
  }

  if (expiresAt !== null && expiresAt - now < EXPIRING_SOON_MS) {
    return { tone: "warn", title: t("keys_banner_expires_soon"), lines: [] };
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
  label = t("keys_subkey_label"),
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
  const dateParts: string[] = [];
  if (row.createdAt !== undefined)
    dateParts.push(
      t("keys_row_created", { date: formatDateShort(row.createdAt) }),
    );
  if (row.expiresAt) {
    const date = formatDateShort(row.expiresAt);
    dateParts.push(
      row.status === "expired"
        ? t("keys_row_expired", { date })
        : t("keys_row_expires", { date }),
    );
  } else if (row.expiresAt === null)
    dateParts.push(t("keys_row_never_expires"));
  const dates = dateParts.map((p) => ` \u00b7 ${p}`).join("");
  return (
    <div className="border-border rounded-md border p-2.5">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-xs font-medium">{label}</span>
        {row.status !== "active" && (
          <span
            className={`rounded-full border px-1.5 py-px text-[10px] font-medium ${STATUS_STYLES[row.status]}`}
          >
            {statusText(row.status)}
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
        {row.bits ? ` (${t("keys_bits", { bits: row.bits })})` : ""}
        {dates}
      </p>
      {row.revocationReason && (
        <p className="mt-1 text-[11px] text-red-400">
          {t("keys_revoked_reason", { reason: row.revocationReason })}
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
  const inactiveLabel = inactiveSubkeys.every((r) => r.status === "expired")
    ? tn("keys_inactive_subkeys_expired", inactiveSubkeys.length)
    : inactiveSubkeys.every((r) => r.status === "revoked")
      ? tn("keys_inactive_subkeys_revoked", inactiveSubkeys.length)
      : tn("keys_inactive_subkeys_unusable", inactiveSubkeys.length);

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
              {t("keys_also_known_as")}
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
        <p className="text-muted-foreground text-xs">{t("keys_loading")}</p>
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
            <InfoRow label={t("keys_fact_fingerprint")}>
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
                  aria-label={t("keys_copy_fingerprint_aria")}
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
          <InfoRow label={t("keys_fact_algorithm")}>
            {formatAlgorithm(facts.algorithm)}
            {primaryRow?.bits
              ? ` · ${t("keys_bits", { bits: primaryRow.bits })}`
              : ""}
          </InfoRow>
          {primaryRow && capabilityText(primaryRow) && (
            <InfoRow label={t("keys_fact_used_for")}>
              {capabilityText(primaryRow)}
            </InfoRow>
          )}
          {facts.createdAt !== undefined && (
            <InfoRow label={t("keys_fact_created")}>
              {formatDate(facts.createdAt)}
            </InfoRow>
          )}
          {facts.expiresAt !== undefined && (
            <InfoRow label={t("keys_fact_expires")}>
              {expiresAt === null ? (
                t("keys_never")
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
                  {t("keys_expires_value", {
                    date: formatDate(expiresAt),
                    when: formatRelative(expiresAt),
                  })}
                </span>
              )}
            </InfoRow>
          )}
          {addedAt !== undefined && (
            <InfoRow label={t("keys_fact_added")}>
              {formatDate(addedAt)}
            </InfoRow>
          )}
          {/* Only own keys track this (bumped on unlock); a contact's
              lastUsedAt is frozen at import time, so showing it would
              just repeat "Added". */}
          {lastUsedAt !== undefined && (
            <InfoRow label={t("keys_fact_last_used")}>
              {formatDate(lastUsedAt)}
            </InfoRow>
          )}
        </div>
      )}

      {facts?.components && (
        <div>
          <h3 className="mb-2 text-xs font-semibold">
            {facts.components.title ?? t("keys_subkeys_title")}{" "}
            <span className="text-muted-foreground font-normal">
              ({subkeys.length})
            </span>
          </h3>
          {facts.components.truncated && (
            <p className="mb-2 text-xs text-amber-400">
              {t("keys_subkeys_truncated", {
                count: facts.components.rows.length,
              })}
            </p>
          )}
          {subkeys.length === 0 && (
            <p className="text-muted-foreground text-xs">
              {t("keys_no_subkeys")}
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
                {inactiveLabel}
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
