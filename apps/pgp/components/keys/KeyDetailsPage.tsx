import { useEffect, useState } from "react";
import {
  CopyIcon,
  DownloadIcon,
  LockIcon,
  PencilIcon,
  StarIcon,
  StarOffIcon,
  Trash2Icon,
} from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import type { KeyDetails, KeyInfo } from "../../lib/pgp/types";
import type {
  ContactRecipient,
  PublicContactKey,
} from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { ComponentKeyRow } from "./key-facts";
import type { KeyPreviewChip } from "./KeyPreviewBody";
import { useCopyToClipboard } from "../../hooks/useCopyToClipboard";
import { t } from "../../lib/i18n";
import { downloadPublicKey } from "../../lib/keys/export-bundle";
import { parseKey, parseKeyDetails } from "../../lib/pgp/wasm";
import {
  contactRecipients,
  isRecipientDisabled,
  setContactRecipientDisabled,
  withRecipientDisabled,
} from "../../lib/storage/contacts";
import { isSshRecord } from "../../lib/storage/key-kind";
import { toast } from "../../lib/toast";
import { downloadText } from "../../lib/utils/download";
import { errorMessage } from "../../lib/utils/errors";
import { parseUserId } from "../../lib/utils/key-naming";
import {
  SlideOverHeader,
  SlideOverPanel,
  useSlideOver,
} from "../shared/SlideOver";
import { pgpKeyFacts, sshGroupKeyFacts, sshKeyFacts } from "./key-facts";
import { KeyPreviewBody } from "./KeyPreviewBody";

export type KeyDetailsTarget =
  | { kind: "own"; keyBlob: ProtectedKeyBlob }
  | { kind: "contact"; contact: PublicContactKey };

interface KeyDetailsPageProps {
  target: KeyDetailsTarget;
  onBack: () => void;
  /** Contacts only: jump to the workspace with this key preselected. */
  onEncryptTo?: () => void;
  /** Open the rename page for this key or contact (local display name
   *  only -- the certificate is never touched). */
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
      label: t("keys_revocation_certificate"),
    });
  };

  const handleGenerate = async () => {
    if (!onGenerate) return;
    setGenerating(true);
    setGenError(null);
    try {
      setCertificate(await onGenerate());
      toast.success(t("keys_revocation_created"), {
        id: "revocation-created",
      });
    } catch (e) {
      setGenError(errorMessage(e, t("keys_revocation_create_failed")));
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div>
      <h3 className="mb-2 text-xs font-semibold">
        {t("keys_revocation_certificate")}
      </h3>
      <div className="border-border space-y-2 rounded-md border p-2.5">
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
              disabled={generating || !onGenerate}
            >
              {generating
                ? t("keys_revocation_creating")
                : t("keys_revocation_create")}
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
  // A contact's key list, held locally so a toggle shows immediately and
  // this page keeps rendering the list it just wrote. Seeded through the
  // accessor, so a legacy single-key record yields its one synthesised
  // entry exactly like every other call site.
  const [recipients, setRecipients] = useState<ContactRecipient[]>(() =>
    target.kind === "contact" ? contactRecipients(target.contact) : [],
  );
  const [savingKeyId, setSavingKeyId] = useState<string | null>(null);
  // More than one key means this contact is a PERSON with several
  // machines, not a certificate: every key gets a row (see
  // `sshGroupKeyFacts`) and every row gets an include/exclude control.
  const multiRecipient = !isOwn && recipients.length > 1;
  const activeCount = recipients.filter((r) => !isRecipientDisabled(r)).length;
  // Which engine this key belongs to. Everything below that reaches for
  // an OpenPGP concept -- the certificate parse, the revocation
  // certificate, being the default key -- is gated on this.
  const isSsh = isSshRecord(isOwn ? target.keyBlob : target.contact);
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

  const primaryUserId = userIds[0] ?? t("keys_unknown_name");
  const { name: rawName, email, comment } = parseUserId(primaryUserId);
  const realName = comment ? `${rawName} (${comment})` : rawName;
  // Local alias wins as the headline; the real identity moves to a
  // subtitle so it's never hidden. Contacts carry one too: an SSH
  // contact's "identity" is a key comment, which may be `user@laptop`,
  // may differ between one person's keys, or may not exist at all.
  const alias = isOwn ? target.keyBlob.alias : target.contact.alias;
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
      label: t("keys_default_badge"),
      title: t("keys_default_title"),
    });
  }
  chips.push({
    label: isOwn ? t("keys_chip_your_key") : t("keys_chip_contact"),
    title: isOwn ? t("keys_chip_your_key_title") : t("keys_chip_contact_title"),
  });
  if (isSsh) {
    chips.push({
      label: "SSH",
      title: t("keys_ssh_chip_title"),
    });
  }
  if (isOwn) {
    chips.push({
      label:
        target.keyBlob.protection.method === "passkey"
          ? t("keys_protection_passkey")
          : t("keys_protection_password"),
      title: t("keys_chip_protection_title"),
    });
  }

  useEffect(() => {
    // An SSH key's "armor" is a recipient line, which the OpenPGP parser
    // rejects -- so parsing it at all would leave this page permanently
    // showing "Could not parse this key". Its facts are already known
    // from the stored record (that is all an SSH key HAS: a fingerprint
    // and an algorithm), so there is nothing to load and nothing to wait
    // for.
    if (isSsh) return;
    let cancelled = false;
    Promise.all([parseKey(armored), parseKeyDetails(armored)])
      .then(([keyInfo, keyDetails]) => {
        if (cancelled) return;
        setInfo(keyInfo);
        setDetails(keyDetails);
      })
      .catch(() => {
        if (!cancelled) setError(t("keys_parse_failed"));
      });
    return () => {
      cancelled = true;
    };
  }, [armored, isSsh]);

  const algorithm = isOwn ? target.keyBlob.algorithm : target.contact.algorithm;
  // Absent sections (health, created, expires, subkeys) simply don't
  // render -- that is the KeyFacts contract. An SSH key is not a
  // certificate with four blanks in it, so nothing explains their
  // absence in their place.
  const facts = multiRecipient
    ? // The import preview already lists every key this way. The details
      // page used to call the SINGLE-key builder regardless, so the two
      // screens -- which share `KeyPreviewBody` precisely so they cannot
      // drift -- disagreed about how many keys the contact had. All of
      // them, each with its FULL fingerprint: those fingerprints are the
      // only out-of-band check the user has that GitHub (or anything in
      // between) didn't hand back a key this person never published.
      sshGroupKeyFacts(recipients)
    : isSsh
      ? sshKeyFacts(
          isOwn ? target.keyBlob.keyId : target.contact.keyId,
          algorithm,
        )
      : info
        ? pgpKeyFacts(info, details)
        : null;

  /** Turn one of this contact's keys on or off, and persist it.
   *
   *  Persisted through `setContactRecipientDisabled` rather than a
   *  `saveContact` of `{ ...target.contact, ... }`, and that is the
   *  whole point: `target.contact` is a snapshot captured when this page
   *  mounted, so saving a spread of it would republish every other field
   *  as it was then -- reverting, say, the expiry backfill that ran in
   *  the meantime. The store re-reads the record inside its own lock and
   *  touches `recipients` alone, which also serialises this write with
   *  the ones `useContacts` makes (its mutex does not reach here).
   *
   *  `withRecipientDisabled` drops the flag entirely when re-enabling,
   *  so nothing ever stores `disabled: false`. Optimistic, with a
   *  rollback: the list on screen must never claim a key is excluded
   *  when the store still has it enabled. */
  const handleToggleRecipient = async (keyId: string, disable: boolean) => {
    if (target.kind !== "contact") return;
    // The last enabled key can never be turned off -- see the disabled
    // control below. Re-checked here because a control is not a
    // guarantee.
    if (disable && activeCount <= 1) return;
    const previous = recipients;
    const next = withRecipientDisabled(previous, keyId, disable);
    setRecipients(next);
    setSavingKeyId(keyId);
    try {
      await setContactRecipientDisabled(target.contact.keyId, keyId, disable);
    } catch (e) {
      setRecipients(previous);
      toast.error(errorMessage(e, t("keys_save_failed")));
    } finally {
      setSavingKeyId(null);
    }
  };

  /** The include/exclude control for one key row. Passed to
   *  `KeyPreviewBody` only from here -- the import preview doesn't pass
   *  it and renders the same rows without controls. */
  const renderRecipientAction = (row: ComponentKeyRow) => {
    const recipient = recipients.find((r) => r.keyId === row.fingerprint);
    if (!recipient) return null;
    const off = isRecipientDisabled(recipient);
    // Refusing to disable the last enabled key is the UI half of the
    // never-encrypt-to-nobody invariant (`activeRecipients` is the
    // other). Dimmed WITH A REASON rather than hidden: a control that
    // vanishes looks like it never existed, so the user is left guessing
    // why this row is different (see `lib/actions/types.ts`).
    const lastActive = !off && activeCount <= 1;
    const busy = savingKeyId === recipient.keyId;
    return (
      <span className="flex items-center gap-1.5">
        {off && (
          <span
            title={t("keys_recipient_off_title")}
            className="rounded-full border border-amber-500/40 bg-amber-500/10 px-1.5 py-px text-[10px] font-medium text-amber-400"
          >
            {t("keys_recipient_not_used")}
          </span>
        )}
        <button
          type="button"
          disabled={busy || lastActive}
          title={
            lastActive
              ? t("keys_recipient_last_active_title")
              : off
                ? t("keys_recipient_enable_title")
                : t("keys_recipient_disable_title")
          }
          onClick={() => void handleToggleRecipient(recipient.keyId, !off)}
          className="text-muted-foreground hover:text-foreground rounded border px-1.5 py-px text-[10px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50"
        >
          {off ? t("keys_recipient_use") : t("keys_recipient_dont_use")}
        </button>
      </span>
    );
  };

  const handleCopyPublicKey = () => {
    void copy(armored, { label: t("common_public_key") });
  };

  const handleDownloadPublicKey = () => {
    // Named after who the key belongs to, not the fingerprint: the file
    // usually ends up attached to a message ("here's Alice's key").
    // `.pub` for an SSH recipient line -- the name every other tool on
    // the machine expects that file under.
    downloadPublicKey(
      armored,
      name || realName || target.kind,
      isSsh ? "pub" : "asc",
    );
  };

  return (
    <SlideOverPanel
      entered={entered}
      ariaLabel={t("keys_details_aria", { name })}
      onDismiss={close}
    >
      <SlideOverHeader title={t("keys_key_details")} onBack={close}>
        {onEncryptTo && (
          <IconAction label={t("keys_encrypt_to")} onClick={onEncryptTo}>
            <LockIcon className="h-4 w-4" />
          </IconAction>
        )}
        {onRename && (
          <IconAction label={t("keys_rename")} onClick={onRename}>
            <PencilIcon className="h-4 w-4" />
          </IconAction>
        )}
        {/* The default key feeds `resolveSelfKey`, which is engine-blind:
            pointing it at an SSH key would make it the preferred
            encrypt-to-self key for PGP messages too, where it can't be
            used. Suppressed rather than disabled -- there is no version
            of this action that does something useful for an SSH key. */}
        {onSetDefault && !isSsh && (
          <IconAction
            label={isDefault ? t("keys_remove_default") : t("keys_set_default")}
            onClick={() => {
              onSetDefault(!isDefault);
              toast.success(
                isDefault ? t("keys_default_removed") : t("keys_default_set"),
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
        <IconAction
          label={t("keys_copy_public_key")}
          onClick={handleCopyPublicKey}
        >
          <CopyIcon className="h-4 w-4" />
        </IconAction>
        <IconAction
          label={t("keys_download_public_key")}
          onClick={handleDownloadPublicKey}
        >
          <DownloadIcon className="h-4 w-4" />
        </IconAction>
        {onDelete && (
          <IconAction
            label={isOwn ? t("keys_delete_key") : t("keys_remove_contact")}
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
          facts={facts}
          // The armor is parsed in an effect, so there genuinely is a
          // gap here where the facts are on their way (unlike the import
          // preview, which is handed a finished classification). An SSH
          // key never parses, so it never waits either.
          loading={!isSsh && !multiRecipient && !info && !error}
          error={error}
          isOwn={isOwn}
          securityWarning={securityWarning}
          addedAt={addedAt}
          lastUsedAt={isOwn ? lastUsedAt : undefined}
          rowAction={multiRecipient ? renderRecipientAction : undefined}
        >
          {/* age has no revocation concept at all -- there is no
              certificate to publish and nobody to publish it to -- so
              the section is absent for an SSH key rather than offering
              a button that cannot work. */}
          {isOwn && !isSsh && (
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
