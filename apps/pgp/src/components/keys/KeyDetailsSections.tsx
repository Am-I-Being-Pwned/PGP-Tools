import { useState } from "react";
import { CheckIcon, ChevronRightIcon, TriangleAlertIcon } from "lucide-react";

import { Block, BlockLabel, Button } from "@amibeingpwned/ui";

import { MarkedText } from "~/components/shared/MarkedText";
import { useAsyncAction, useCopyToClipboard } from "~/hooks";
import { AppError } from "~/lib/errors/app-error";
import { presentError } from "~/lib/errors/present";
import { t } from "~/lib/i18n";
import { formatDate } from "~/lib/i18n/format";
import type { IdentityConflict, IdentityHolder } from "~/lib/identity/binding";
import { clashSentence } from "~/lib/identity/clash-copy";
import { toast } from "~/lib/toast";
import { downloadText } from "~/lib/utils/download";

export function IconAction({
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
      <span className="surface-float text-foreground pointer-events-none absolute top-full right-0 z-10 mt-1 hidden rounded-md px-1.5 py-0.5 text-[10px] whitespace-nowrap peer-hover:block">
        {label}
      </span>
    </span>
  );
}

export function RevocationSection({
  keyId,
  initialCertificate,
  onGenerate,
}: {
  keyId: string;
  initialCertificate?: string;
  onGenerate?: () => Promise<string>;
}) {
  const [certificate, setCertificate] = useState(initialCertificate ?? null);
  // A locked key's message is ours and actionable; engine failures stay
  // generic.
  const generate = useAsyncAction((e) =>
    e instanceof AppError && e.code === "key-locked"
      ? { message: e.message }
      : presentError(e, t("keys_revocation_create_failed")),
  );

  const handleDownload = () => {
    if (!certificate) return;
    downloadText(certificate, `revocation-${keyId.slice(-16)}.asc`);
  };

  const { copy } = useCopyToClipboard();
  const handleCopy = () => {
    if (!certificate) return;
    // A revocation cert is an irreversible instrument (anyone holding it
    // can revoke the key), so the toast says it now sits on the clipboard
    // and in any clipboard history, as for an exported private key.
    void copy(certificate, {
      sensitive: true,
      label: t("keys_revocation_certificate"),
    });
  };

  const handleGenerate = () =>
    generate.run(async () => {
      if (!onGenerate) return;
      setCertificate(await onGenerate());
      toast.success(t("keys_revocation_created"), {
        id: "revocation-created",
      });
    });

  return (
    <div>
      <BlockLabel as="h3" className="mb-1.5">
        {t("keys_revocation_certificate")}
      </BlockLabel>
      <Block className="space-y-2 rounded-xl px-3.5 py-3">
        <p className="text-muted-foreground text-xs">
          {certificate
            ? t("keys_revocation_have_body")
            : t("keys_revocation_missing_body")}
        </p>
        {certificate ? (
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={handleDownload}>
              {t("common_download")}
            </Button>
            <Button variant="outline" size="sm" onClick={handleCopy}>
              {t("common_copy")}
            </Button>
          </div>
        ) : (
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void handleGenerate()}
              disabled={generate.busy || !onGenerate}
            >
              {generate.busy
                ? t("keys_revocation_creating")
                : t("keys_revocation_create")}
            </Button>
            {generate.error && (
              <p className="text-destructive text-xs" role="alert">
                {generate.error.message}
              </p>
            )}
          </>
        )}
      </Block>
    </div>
  );
}

// ── identity clash (contacts) ────────────────────────────────────────

/** Who else claims this contact's address or name, one line per key,
 *  each a click from its own details: the card's "Same address" pill
 *  says THAT there is another key; this says which, so the user can
 *  compare the two fingerprints with the person. */
export function ClashBand({
  clash,
  onShowHolder,
}: {
  clash: IdentityConflict;
  onShowHolder?: (holder: IdentityHolder) => void;
}) {
  return (
    <Block className="space-y-1.5 bg-[#252012] px-3.5 py-2.5">
      {clash.holders.map((holder) => (
        <div key={holder.keyId} className="flex items-start gap-1.5">
          <TriangleAlertIcon className="text-warn mt-0.5 h-3.5 w-3.5 shrink-0" />
          <p className="text-warn min-w-0 flex-1 text-xs leading-relaxed">
            <MarkedText text={clashSentence(clash, holder)} />
          </p>
          {onShowHolder && (
            <button
              type="button"
              aria-label={t("keys_key_details")}
              title={t("keys_key_details")}
              onClick={() => onShowHolder(holder)}
              className="text-warn hover:bg-warn/12 -my-0.5 shrink-0 rounded p-0.5 transition-colors"
            >
              <ChevronRightIcon className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      ))}
      <p className="text-muted-foreground pl-5 text-xs leading-relaxed">
        {t("keys_clash_check")}
      </p>
    </Block>
  );
}

// ── verification (contacts) ──────────────────────────────────────────

/** "Mark as verified": the user's own record that they compared this
 *  fingerprint with its owner. Nothing else sets it -- not an import, not
 *  a keyserver, not a signature -- so it is the one statement about who
 *  a key belongs to that the user made themselves. */
export function VerifySection({
  name,
  verified,
  verifiedAt,
  onSetVerified,
}: {
  name: string;
  verified: boolean;
  verifiedAt?: number;
  onSetVerified: (verified: boolean) => Promise<void>;
}) {
  const { run, busy } = useAsyncAction(t("keys_save_failed"));
  const set = async (next: boolean) => {
    const error = await run(() => onSetVerified(next));
    if (error) toast.error(error.message);
  };
  if (verified) {
    return (
      <Block className="flex items-center gap-2 px-3.5 py-2.5">
        <CheckIcon className="text-good h-3.5 w-3.5 shrink-0" />
        <p className="min-w-0 flex-1 text-xs">
          {verifiedAt !== undefined
            ? t("keys_verified_on", { date: formatDate(verifiedAt) })
            : t("keys_verified_by_you")}
        </p>
        <Button
          variant="ghost"
          size="sm"
          className="text-muted-foreground h-7 px-2"
          disabled={busy}
          onClick={() => void set(false)}
        >
          {t("keys_verified_unmark")}
        </Button>
      </Block>
    );
  }
  return (
    <Block className="space-y-2 px-3.5 py-2.5">
      <p className="text-muted-foreground text-xs leading-relaxed">
        {t("keys_verify_hint", { name })}
      </p>
      <Button
        variant="outline"
        size="sm"
        disabled={busy}
        onClick={() => void set(true)}
      >
        {t("keys_verify_mark")}
      </Button>
    </Block>
  );
}
