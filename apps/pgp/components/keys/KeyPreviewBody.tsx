import { Fragment, useEffect, useRef, useState } from "react";
import {
  CheckIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  CopyIcon,
  TriangleAlertIcon,
  XCircleIcon,
} from "lucide-react";

import { cn } from "@amibeingpwned/ui";
import { Block, BlockStack } from "@amibeingpwned/ui/block";

import type { ComponentKeyRow, KeyFacts, KeyHealth } from "./key-facts";
import { useCopyToClipboard } from "../../hooks/useCopyToClipboard";
import { t, tn } from "../../lib/i18n";
import {
  formatDate,
  formatDateShort,
  formatRelative,
} from "../../lib/i18n/format";
import { formatAlgorithm } from "../../lib/utils/formatting";
import { KeyAvatar } from "../shared/KeyAvatar";
import { MarkedText } from "../shared/MarkedText";
import { fingerprintLines } from "./fingerprint-lines";

/**
 * The read-only body of a key: identity card (face, names, health
 * banner), the fingerprint, the facts card (algorithm, dates) and the
 * subkey list.
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

/** The design language's status pill; the tone classes are added per use. */
const PILL = "rounded px-1.5 py-px text-[10.5px] font-medium whitespace-nowrap";

const STATUS_STYLES: Record<ComponentKeyRow["status"], string> = {
  active: "bg-good/12 text-good",
  expired: "bg-warn/12 text-warn",
  revoked: "bg-destructive/12 text-bad",
  invalid: "bg-destructive/12 text-bad",
};

/** What this component key is used for, one plain word per capability. */
function capabilities(row: ComponentKeyRow): string[] {
  const parts: string[] = [];
  if (row.canSign) parts.push(t("keys_cap_sign"));
  if (row.canEncrypt) parts.push(t("keys_cap_encrypt"));
  if (row.canAuthenticate) parts.push(t("keys_cap_auth"));
  if (row.canCertify) parts.push(t("keys_cap_certify"));
  return parts;
}

/** The same, as one line ("Sign · Encrypt"). */
function capabilityText(row: ComponentKeyRow): string {
  return capabilities(row).join(" · ");
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

// A status band: the block under the key's face, tinted for the outcome.
const BANNER_STYLES: Record<Banner["tone"], { box: string; title: string }> = {
  warn: { box: "bg-[#252012]", title: "text-warn" },
  bad: { box: "bg-[#2a1517]", title: "text-bad" },
};

function StatusBanner({ banner }: { banner: Banner }) {
  const styles = BANNER_STYLES[banner.tone];
  const Icon = banner.tone === "warn" ? TriangleAlertIcon : XCircleIcon;
  return (
    <Block className={cn("px-3.5 py-2.5", styles.box)}>
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
    </Block>
  );
}

// ── building blocks ──────────────────────────────────────────────────

/** One block of the facts card; the parent stacks them. */
function InfoRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <Block className="flex gap-3 px-3.5 py-2.5 text-xs">
      <span className="text-muted-foreground w-20 shrink-0">{label}</span>
      <span className="min-w-0 flex-1">{children}</span>
    </Block>
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
      className={cn(PILL, "bg-secondary text-muted-foreground")}
    >
      {children}
    </span>
  );
}

/**
 * A fingerprint for reading: exactly the lines `fingerprintLines` gives
 * (a hex one as rows of five 4-character groups, GnuPG's layout, so two
 * can be compared block by block; anything else as one unbroken line),
 * each as plain spaced text in mono -- the monospace face lines the
 * groups up into columns on its own. Plain text on purpose: selecting
 * and copying it by hand yields the same text the copy button does,
 * row by row, rather than one group per line.
 */
function FingerprintText({
  fingerprint,
  className,
}: {
  fingerprint: string;
  className?: string;
}) {
  const lines = fingerprintLines(fingerprint);
  // Hex groups alternate bright and dim, counted across BOTH lines, so
  // reading along a row or down a column the eye can hold its place --
  // the grid you read aloud on a call. Each line stays one run of text
  // with real spaces (justified out to full width, which monospace
  // turns into even columns), so a manual select-and-copy gives the
  // same "3C71 E09A ..." the copy button does. A non-hex fingerprint
  // (OpenSSH `SHA256:...`) is one unbroken line and is left as it is.
  let group = 0;
  return (
    <span className={cn("block font-mono break-all", className)}>
      {lines.map((line) => {
        const groups = line.split(" ");
        if (groups.length < 2)
          return (
            <span key={line} className="block">
              {line}
            </span>
          );
        return (
          <span
            key={line}
            className="block text-justify [text-align-last:justify]"
          >
            {groups.map((g, i) => (
              <Fragment key={i}>
                {i > 0 && " "}
                <span
                  className={
                    group++ % 2 === 0
                      ? "text-foreground"
                      : "text-muted-foreground"
                  }
                >
                  {g}
                </span>
              </Fragment>
            ))}
          </span>
        );
      })}
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
  const caps = capabilities(row);
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
    <Block className="px-3.5 py-2.5">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-xs font-medium">{label}</span>
        {row.status !== "active" && (
          <span className={cn(PILL, STATUS_STYLES[row.status])}>
            {statusText(row.status)}
          </span>
        )}
        {caps.map((cap) => (
          <span
            key={cap}
            className={cn(PILL, "bg-secondary text-muted-foreground")}
          >
            {cap}
          </span>
        ))}
        {action && <span className="ml-auto">{action}</span>}
      </div>
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
        <p className="text-bad mt-1 text-[11px]">
          {t("keys_revoked_reason", { reason: row.revocationReason })}
        </p>
      )}
      {row.policyError && (
        <p className="text-warn mt-1 text-[11px]">{row.policyError}</p>
      )}
    </Block>
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
  /** What the key's face is drawn from: the stored or
   *  incoming record's fingerprint. Absent ⇒ no face. */
  avatarFingerprint?: string;
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
  /** Blocks stacked under the fingerprint: the contact's "Mark as
   *  verified", which is about exactly that fingerprint. */
  fingerprintFooter?: React.ReactNode;
  /** Per-row control rendered in each component-key row's header. The
   *  import preview doesn't pass it; the details page uses it to hang an
   *  include/exclude toggle off each of a contact's keys. */
  rowAction?: (row: ComponentKeyRow) => React.ReactNode;
}

export function KeyPreviewBody({
  name,
  avatarFingerprint,
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
  fingerprintFooter,
  rowAction,
}: KeyPreviewBodyProps) {
  const [showInactive, setShowInactive] = useState(false);
  const [copiedFp, setCopiedFp] = useState(false);
  const copyTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const [copiedEmail, setCopiedEmail] = useState(false);
  const emailTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const { copy } = useCopyToClipboard();

  useEffect(() => {
    return () => {
      clearTimeout(copyTimer.current);
      clearTimeout(emailTimer.current);
    };
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
  // How far through its validity the key is (created -> expires), only
  // when the facts carry both ends -- never guessed. Toned by the same
  // expired / expiring-soon / revoked states the text above already uses.
  const createdAt = facts?.createdAt;
  const validity =
    createdAt !== undefined && expiresAt !== null && expiresAt > createdAt
      ? Math.min(1, Math.max(0, (now - createdAt) / (expiresAt - createdAt)))
      : null;
  const validityTone =
    keyExpired || primaryRow?.status === "revoked"
      ? "bg-destructive"
      : keyExpiringSoon
        ? "bg-warn"
        : "bg-muted-foreground/60";
  const handleCopyEmail = (address: string) => {
    void copy(address).then((ok) => {
      if (!ok) return;
      setCopiedEmail(true);
      clearTimeout(emailTimer.current);
      emailTimer.current = setTimeout(() => setCopiedEmail(false), 2000);
    });
  };

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
      {/* The identity card: the key's face and names, then -- as bands
          under it -- whatever this screen has to say about the key. */}
      <BlockStack>
        <Block className="flex items-center gap-4 p-4">
          {avatarFingerprint && (
            <KeyAvatar fingerprint={avatarFingerprint} size={64} />
          )}
          <div className="min-w-0 flex-1">
            <p className="truncate text-base leading-tight font-semibold">
              <MarkedText text={name} />
            </p>
            {subtitle && (
              <p className="text-muted-foreground mt-0.5 truncate text-xs">
                {subtitle}
              </p>
            )}
            {email && (
              <p className="text-muted-foreground mt-0.5 flex min-w-0 items-center gap-1 text-xs">
                <span className="truncate">
                  <MarkedText text={email} />
                </span>
                <button
                  type="button"
                  onClick={() => handleCopyEmail(email)}
                  aria-label={t("keys_copy_email_aria")}
                  title={t("keys_copy_email_aria")}
                  className="hover:text-foreground shrink-0 rounded p-0.5 transition-colors"
                >
                  {copiedEmail ? (
                    <CheckIcon className="text-good h-3 w-3" />
                  ) : (
                    <CopyIcon className="h-3 w-3" />
                  )}
                </button>
              </p>
            )}
            {chips.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {chips.map((chip) => (
                  <Chip key={chip.label} title={chip.title}>
                    {chip.label}
                  </Chip>
                ))}
              </div>
            )}
          </div>
        </Block>
        {akaEmails.length > 0 && (
          <Block className="px-3.5 py-2.5">
            <p className="text-muted-foreground text-[10px] font-medium tracking-wide uppercase">
              {t("keys_also_known_as")}
            </p>
            {akaEmails.map((aka) => (
              <p key={aka} className="text-muted-foreground text-xs">
                {aka}
              </p>
            ))}
          </Block>
        )}

        {statusStrip}

        {banner && <StatusBanner banner={banner} />}

        {securityWarning && (
          <Block className="flex items-start gap-1.5 bg-[#252012] px-3.5 py-2.5">
            <TriangleAlertIcon className="text-warn mt-0.5 h-3.5 w-3.5 shrink-0" />
            <p className="text-warn text-xs leading-relaxed">
              {securityWarning}
            </p>
          </Block>
        )}
      </BlockStack>

      {error && <p className="text-destructive px-1 text-xs">{error}</p>}
      {!error && loading && (
        <p className="text-muted-foreground px-1 text-xs">
          {t("keys_loading")}
        </p>
      )}

      {facts?.fingerprint !== undefined && (
        <div>
          <div className="mb-1.5 flex items-center justify-between px-1">
            <span className="text-muted-foreground text-xs font-medium">
              {t("keys_fact_fingerprint")}
            </span>
            <button
              type="button"
              onClick={() => handleCopyFingerprint(facts.fingerprint ?? "")}
              aria-label={t("keys_copy_fingerprint_aria")}
              className="text-muted-foreground hover:text-foreground -my-0.5 flex items-center gap-1 rounded px-1 py-0.5 text-xs font-medium transition-colors"
            >
              {copiedFp && <CheckIcon className="text-good h-3 w-3" />}
              {t("common_copy")}
            </button>
          </div>
          <BlockStack>
            <Block className="px-3.5 py-3">
              <FingerprintText
                fingerprint={facts.fingerprint}
                className="text-[13px] leading-relaxed tracking-wide"
              />
            </Block>
            {fingerprintFooter}
          </BlockStack>
        </div>
      )}

      {facts && (
        <BlockStack>
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
                      ? "text-bad"
                      : keyExpiringSoon
                        ? "text-warn"
                        : undefined
                  }
                >
                  {t("keys_expires_value", {
                    date: formatDate(expiresAt),
                    when: formatRelative(expiresAt),
                  })}
                </span>
              )}
              {validity !== null && (
                <span
                  aria-hidden="true"
                  className="bg-accent mt-2 block h-[3px] overflow-hidden rounded-full"
                >
                  <span
                    className={cn("block h-full rounded-full", validityTone)}
                    style={{ width: `${validity * 100}%` }}
                  />
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
        </BlockStack>
      )}

      {facts?.components && (
        <div>
          <h3 className="text-muted-foreground mb-1.5 px-1 text-xs font-medium">
            {facts.components.title ?? t("keys_subkeys_title")}{" "}
            <span className="font-normal">({subkeys.length})</span>
          </h3>
          {facts.components.truncated && (
            <p className="text-warn mb-1.5 px-1 text-xs">
              {t("keys_subkeys_truncated", {
                count: facts.components.rows.length,
              })}
            </p>
          )}
          {subkeys.length === 0 && (
            <p className="text-muted-foreground px-1 text-xs">
              {t("keys_no_subkeys")}
            </p>
          )}
          {activeSubkeys.length > 0 && (
            <BlockStack>
              {activeSubkeys.map((row) => (
                <SubkeyRow
                  key={row.fingerprint}
                  row={row}
                  label={facts.components?.rowLabel}
                  action={rowAction?.(row)}
                />
              ))}
            </BlockStack>
          )}
          {inactiveSubkeys.length > 0 && (
            <div className="mt-2">
              <button
                type="button"
                onClick={() => setShowInactive((v) => !v)}
                aria-expanded={showInactive}
                className="text-muted-foreground hover:text-foreground flex items-center gap-1 px-1 py-1 text-xs transition-colors"
              >
                {showInactive ? (
                  <ChevronDownIcon className="h-3.5 w-3.5" />
                ) : (
                  <ChevronRightIcon className="h-3.5 w-3.5" />
                )}
                {inactiveLabel}
              </button>
              {showInactive && (
                <BlockStack className="mt-1">
                  {inactiveSubkeys.map((row) => (
                    <SubkeyRow
                      key={row.fingerprint}
                      row={row}
                      label={facts.components?.rowLabel}
                      action={rowAction?.(row)}
                    />
                  ))}
                </BlockStack>
              )}
            </div>
          )}
        </div>
      )}

      {children}
    </>
  );
}
