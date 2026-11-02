import { useEffect, useMemo, useState } from "react";
import {
  CopyIcon,
  DownloadIcon,
  LockIcon,
  PencilIcon,
  ShieldQuestionIcon,
  StarIcon,
  StarOffIcon,
  Trash2Icon,
} from "lucide-react";

import {
  SlideOverHeader,
  SlideOverPanel,
  useSlideOver,
} from "~/components/shared/SlideOver";
import { useContacts, useCopyToClipboard, useKeyring } from "~/hooks";
import { t } from "~/lib/i18n";
import {
  contactClashes,
  type IdentityConflict,
  type IdentityHolder,
} from "~/lib/identity/binding";
import { downloadPublicKey } from "~/lib/keys/export-bundle";
import type { KeyDetails, KeyInfo } from "~/lib/pgp/types";
import { parseKey, parseKeyDetails } from "~/lib/pgp/wasm";
import {
  setContactRecipientDisabled,
  setContactVerified,
  type PublicContactKey,
} from "~/lib/storage/contacts";
import { isSshRecord } from "~/lib/storage/key-kind";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import { toast } from "~/lib/toast";
import { parseUserId, realIdentity } from "~/lib/utils/key-naming";
import { pgpKeyFacts, sshGroupKeyFacts, sshKeyFacts } from "./key-facts";
import {
  ClashBand,
  IconAction,
  RevocationSection,
  VerifySection,
} from "./KeyDetailsSections";
import { KeyPreviewBody, type KeyPreviewChip } from "./KeyPreviewBody";
import { holderDetailsTarget } from "./keys-routes";
import { useRecipientToggles } from "./useRecipientToggles";

export type KeyDetailsTarget =
  | { kind: "own"; keyBlob: ProtectedKeyBlob }
  | { kind: "contact"; contact: PublicContactKey };

interface KeyDetailsPageProps {
  target: KeyDetailsTarget;
  onBack: () => void;
  onEncryptTo?: () => void;
  /** Local display name only; the certificate is never touched. */
  onRename?: () => void;
  onCheckRevocation?: () => void;
  onSetVerified?: (verified: boolean) => Promise<void>;
  clash?: IdentityConflict;
  onShowHolder?: (holder: IdentityHolder) => void;
  isDefault?: boolean;
  onSetDefault?: (next: boolean) => void;
  onDelete?: () => void;
  /** Should throw a user-readable message when the key is locked. */
  onGenerateRevocation?: () => Promise<string>;
}

// ── page ─────────────────────────────────────────────────────────────

export function KeyDetailsPage({
  target: targetProp,
  onBack,
  onEncryptTo,
  onRename,
  onCheckRevocation,
  onSetVerified: onSetVerifiedProp,
  clash: clashProp,
  onShowHolder: onShowHolderProp,
  isDefault,
  onSetDefault,
  onDelete,
  onGenerateRevocation,
}: KeyDetailsPageProps) {
  const { entered, close } = useSlideOver(onBack);
  // Clash, holder and verify are derived from the stores unless the caller
  // wires its own; explicit props win.
  const { contacts } = useContacts();
  const { keys: ownKeys } = useKeyring();
  // The contact as it is in the live list when one was handed in: the
  // target is a snapshot from when the page opened, and Mark as verified
  // has to show its answer here.
  const liveContact =
    targetProp.kind === "contact"
      ? contacts.find((c) => c.keyId === targetProp.contact.keyId)
      : undefined;
  const target: KeyDetailsTarget = liveContact
    ? { kind: "contact", contact: liveContact }
    : targetProp;
  const contactKeyId = target.kind === "contact" ? target.contact.keyId : null;
  const derivedClash = useMemo(
    () =>
      contactKeyId !== null
        ? contactClashes(contacts, ownKeys).get(contactKeyId)
        : undefined,
    [contactKeyId, contacts, ownKeys],
  );
  const clash = clashProp ?? derivedClash;
  // A clash holder opened on top of this page, for an entry point with
  // no navigation stack of its own.
  const [holderTarget, setHolderTarget] = useState<KeyDetailsTarget | null>(
    null,
  );
  const onShowHolder =
    onShowHolderProp ??
    ((holder: IdentityHolder) => {
      const next = holderDetailsTarget(holder.keyId, contacts, ownKeys);
      if (next) setHolderTarget(next);
    });
  // Only for a contact actually in the store (`liveContact`), and not a
  // revoked one -- the same rule the Keys tab applies.
  const onSetVerified =
    onSetVerifiedProp ??
    (liveContact && !liveContact.revoked
      ? (verified: boolean) => setContactVerified(liveContact.keyId, verified)
      : undefined);
  const [info, setInfo] = useState<KeyInfo | null>(null);
  const [details, setDetails] = useState<KeyDetails | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { copy } = useCopyToClipboard();

  const isOwn = target.kind === "own";
  const { recipients, multiRecipient, renderRecipientAction } =
    useRecipientToggles(target, (keyId, disable) =>
      target.kind === "contact"
        ? setContactRecipientDisabled(target.contact.keyId, keyId, disable)
        : Promise.resolve(),
    );
  // Which engine this key belongs to. Everything below that reaches for
  // an OpenPGP concept -- the certificate parse, the revocation
  // certificate, being the default key -- is gated on this.
  const record = isOwn ? target.keyBlob : target.contact;
  const isSsh = isSshRecord(record);
  const { userIds, securityWarning, lastUsedAt, alias, algorithm } = record;
  const armored = isOwn
    ? target.keyBlob.publicKeyArmored
    : target.contact.armoredPublicKey;
  const addedAt = isOwn ? target.keyBlob.createdAt : target.contact.addedAt;

  const { email } = parseUserId(userIds[0]);
  const realName = realIdentity(userIds[0]);
  // The alias heads the page; the real identity stays visible under it.
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
  const verifiedAt =
    target.kind === "contact" && target.contact.verified
      ? target.contact.verifiedAt
      : undefined;
  const verified = target.kind === "contact" && !!target.contact.verified;
  if (verified) {
    chips.push({
      label: t("keys_verified_chip"),
      title: t("keys_verified_chip_title"),
    });
  }
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
      ? sshKeyFacts(record.keyId, algorithm)
      : info
        ? pgpKeyFacts(info, details)
        : null;

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
    <>
      <SlideOverPanel
        entered={entered}
        ariaLabel={t("keys_details_aria", { name })}
        onDismiss={close}
      >
        {/* No visible title: the identity card right under it says whose
          key this is, and the header's actions need the width. */}
        <SlideOverHeader title={t("keys_key_details")} hideTitle onBack={close}>
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
          {onCheckRevocation && (
            <IconAction
              label={t("keys_check_revocation")}
              onClick={onCheckRevocation}
            >
              <ShieldQuestionIcon className="h-4 w-4" />
            </IconAction>
          )}
          {/* The default key feeds `resolveSelfKey`, which is engine-blind:
            pointing it at an SSH key would make it the preferred
            encrypt-to-self key for PGP messages too, where it can't be
            used. Suppressed rather than disabled -- there is no version
            of this action that does something useful for an SSH key. */}
          {onSetDefault && !isSsh && (
            <IconAction
              label={
                isDefault ? t("keys_remove_default") : t("keys_set_default")
              }
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

        <div className="flex-1 space-y-3 overflow-y-auto p-3">
          <KeyPreviewBody
            name={name}
            // The record's own id: the hex fingerprint, or an SSH key's
            // `SHA256:` hash -- for a multi-key contact, its first key's,
            // which is the record's identity (see `recipientsField`).
            avatarFingerprint={record.keyId}
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
            statusStrip={
              clash && <ClashBand clash={clash} onShowHolder={onShowHolder} />
            }
            addedAt={addedAt}
            lastUsedAt={isOwn ? lastUsedAt : undefined}
            rowAction={multiRecipient ? renderRecipientAction : undefined}
            fingerprintFooter={
              onSetVerified && (
                <VerifySection
                  name={name}
                  verified={verified}
                  verifiedAt={verifiedAt}
                  onSetVerified={onSetVerified}
                />
              )
            }
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
      {holderTarget && (
        <KeyDetailsPage
          target={holderTarget}
          onBack={() => setHolderTarget(null)}
        />
      )}
    </>
  );
}
