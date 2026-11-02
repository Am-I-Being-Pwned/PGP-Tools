import {
  AlertTriangleIcon,
  CheckCircleIcon,
  RefreshCwIcon,
} from "lucide-react";

import { Block, BlockStack, Button, Input, Kbd } from "@amibeingpwned/ui";

import {
  SlideOverHeader,
  SlideOverPanel,
  useSlideOver,
} from "~/components/shared/SlideOver";
import { t, tn } from "~/lib/i18n";
import { formatDate } from "~/lib/i18n/format";
import {
  isPublicKind,
  type IncomingKey,
  type KeyKind,
} from "~/lib/import/types";
import { parseUserId } from "~/lib/utils/key-naming";
import { pgpKeyFacts, sshGroupKeyFacts, sshKeyFacts } from "./key-facts";
import { KeyPreviewBody, type KeyPreviewChip } from "./KeyPreviewBody";

/**
 * The key about to be imported, in the same body as the details page.
 * Armor is never rendered; secret material never reaches this component.
 */

/** Only exceptions get a strip. A rejected key gets none: the health
 *  banner already says why, and two red boxes read as two problems. */
function ImportStatusStrip({ incoming }: { incoming: IncomingKey }) {
  const { status, changes, existingAddedAt, replaces } = incoming;
  if (status === "new" && replaces) {
    // Importing swaps the key this contact is encrypted to: never shown as new.
    return (
      <Block className="bg-[#252012] px-3.5 py-2.5">
        <p className="text-warn flex items-center gap-1.5 text-xs font-medium">
          <AlertTriangleIcon className="h-3.5 w-3.5 shrink-0" />
          {t("import_status_replaces", { name: replaces })}
        </p>
      </Block>
    );
  }
  if (status === "new" || status === "rejected") return null;

  const added = existingAddedAt != null ? formatDate(existingAddedAt) : null;

  if (status === "duplicate") {
    return (
      <Block className="bg-[#15231b] px-3.5 py-2.5">
        <p className="text-good flex items-center gap-1.5 text-xs font-medium">
          <CheckCircleIcon className="h-3.5 w-3.5 shrink-0" />
          {t("import_status_duplicate")}
        </p>
        {added && (
          <p className="text-muted-foreground mt-1 pl-5 text-xs">
            {t("import_status_duplicate_added", { date: added })}
          </p>
        )}
      </Block>
    );
  }

  return (
    <Block className="px-3.5 py-2.5">
      <p className="text-foreground flex items-center gap-1.5 text-xs font-medium">
        <RefreshCwIcon className="h-3.5 w-3.5 shrink-0" />
        {t("import_status_update")}
      </p>
      <div className="mt-1 space-y-0.5 pl-5">
        {added && (
          <p className="text-muted-foreground text-xs">
            {t("import_status_added_on", { date: added })}
          </p>
        )}
        {changes.map((change) => (
          <p key={change} className="text-muted-foreground text-xs">
            {change}
          </p>
        ))}
      </div>
    </Block>
  );
}

function actionLabel(incoming: IncomingKey): string {
  if (!isPublicKind(incoming.kind)) {
    // Replacing a stored private key also discards its protection and passkey
    // binding, so the label says so.
    return incoming.status === "update"
      ? t("import_action_replace_stored")
      : t("common_continue");
  }
  return incoming.status === "update"
    ? t("import_action_update_contact")
    : t("import_action_import_contact");
}

/** A Record so a new {@link KeyKind} is a type error until labelled. */
const KIND_CHIPS: Record<KeyKind, () => KeyPreviewChip> = {
  "pgp-private": () => ({
    label: t("common_private_key"),
    title: t("import_chip_pgp_private_title"),
  }),
  "pgp-public": () => ({
    label: t("common_public_key"),
    title: t("import_chip_pgp_public_title"),
  }),
  "ssh-private": () => ({
    label: t("import_chip_ssh_private"),
    title: t("import_chip_ssh_private_title"),
  }),
  "ssh-public": () => ({
    label: t("import_chip_ssh_public"),
    title: t("import_chip_ssh_public_title"),
  }),
  crx: () => ({
    label: t("import_chip_crx"),
    title: t("import_chip_crx_title"),
  }),
};

/** Read off `publicArmored`, the canonical line wasm returned, so it
 *  can't disagree with what gets stored. */
function sshAlgorithm(recipientLine: string): string {
  return recipientLine.trim().split(/\s+/)[0] ?? "";
}

interface ImportPreviewProps {
  incoming: IncomingKey;
  onConfirm?: () => void;
  onDone: () => void;
  onReveal?: () => void;
  busy?: boolean;
  error?: string | null;
  /**
   * Offering to file several pasted keys as one contact. Nothing in the text
   * says they are one person, so blank (import separately) is the default.
   */
  grouping?: {
    name: string;
    onNameChange: (name: string) => void;
    separateCount: number;
  };
}

export function ImportPreview({
  incoming,
  onConfirm,
  onDone,
  onReveal,
  busy,
  error,
  grouping,
}: ImportPreviewProps) {
  const primaryUserId = incoming.userIds[0] ?? t("import_unknown_name");
  const { name: rawName, email, comment } = parseUserId(primaryUserId);
  const name = comment ? `${rawName} (${comment})` : rawName;

  const akaEmails = Array.from(
    new Set(
      incoming.userIds
        .slice(1)
        .map((uid) => parseUserId(uid).email || uid)
        .filter((e) => e !== email),
    ),
  );

  const chips: KeyPreviewChip[] = [KIND_CHIPS[incoming.kind]()];
  // A person with several keys says so up front: the count is the one
  // thing about a group that isn't visible from the headline, and it is
  // what explains the list of fingerprints further down.
  if (incoming.group && incoming.group.members.length > 1) {
    chips.push({
      label: tn("import_group_keys_chip", incoming.group.members.length),
      title: t("import_group_keys_chip_title"),
    });
  }

  // An SSH public key parses to a fingerprint and an algorithm and
  // nothing else, so it gets the two-row facts card rather than the
  // certificate one; `ssh-private` and `crx` have no public half to show
  // at all yet and get words instead (see below).
  const facts =
    incoming.info !== null
      ? pgpKeyFacts(incoming.info, incoming.details)
      : // A fetched contact is one person with several keys: same card,
        // with a row per key rather than a single fingerprint (see
        // sshGroupKeyFacts). A group whose members are all unusable has
        // none to list and falls through to the one-key card, which has
        // nothing to show either -- the rejection reason below is the
        // whole story in that case.
        incoming.group && incoming.group.members.length > 0
        ? sshGroupKeyFacts(incoming.group.members)
        : incoming.kind === "ssh-public"
          ? sshKeyFacts(incoming.keyId, sshAlgorithm(incoming.publicArmored))
          : null;

  const canConfirm =
    !!onConfirm &&
    incoming.status !== "duplicate" &&
    incoming.status !== "rejected";

  return (
    <div className="flex flex-1 flex-col overflow-hidden">
      <div className="flex-1 space-y-3 overflow-y-auto p-3">
        <KeyPreviewBody
          name={name}
          avatarFingerprint={incoming.keyId}
          email={email}
          akaEmails={akaEmails}
          chips={chips}
          // Nothing is loading here: the classification is already done by
          // the time this renders, so a key with no facts (a CRX signing
          // key) shows what it has and stops -- it never waits.
          facts={facts}
          isOwn={
            incoming.kind === "pgp-private" || incoming.kind === "ssh-private"
          }
          securityWarning={incoming.securityWarning}
          statusStrip={<ImportStatusStrip incoming={incoming} />}
        >
          {grouping && (
            /* The one thing the keys cannot say for themselves. Named
               like the CRX label field on the protect step, and optional
               in the same way -- leaving it blank is a real answer, not
               a skipped step, so the footer button says which one it is
               rather than making the user infer it. */
            <div>
              <label className="text-muted-foreground mb-1.5 block px-1 text-xs font-medium">
                {t("import_group_label")}{" "}
                <span className="text-muted-foreground/60">
                  {t("import_optional")}
                </span>
              </label>
              <Input
                type="text"
                autoFocus
                maxLength={200}
                placeholder={t("import_group_placeholder")}
                value={grouping.name}
                onChange={(e) => grouping.onNameChange(e.target.value)}
                onKeyDown={(e) => {
                  // This field is autofocused, so it -- not the button --
                  // is what Return reaches when a group is being named.
                  // Without this the chip on the button below would be a
                  // lie in exactly the case where the user is most
                  // likely to press Return: they have just typed a name.
                  if (e.key === "Enter" && !busy && canConfirm) {
                    e.preventDefault();
                    onConfirm();
                  }
                }}
              />
              <p className="text-muted-foreground mt-1.5 px-1 text-[11px]">
                {tn("import_group_help", grouping.separateCount)}
              </p>
            </div>
          )}
          {incoming.group?.source && (
            /* Where it came from, and -- the part that must not be
               swallowed -- every line the engine refused, in its own
               words. A key missing from someone's recipient list shows
               up as "they can't read my message", never as an error, so
               the refusal is said here, before the import. */
            <div className="space-y-2">
              <p className="text-muted-foreground text-xs">
                {t("import_github_fetched_note", {
                  user: incoming.group.source.user,
                })}
              </p>
              {incoming.group.rejected.length > 0 && (
                <div className="space-y-1.5">
                  <p className="text-warn px-1 text-xs font-medium">
                    {tn(
                      "import_github_rejected_heading",
                      incoming.group.rejected.length,
                    )}
                  </p>
                  <BlockStack>
                    {incoming.group.rejected.map((r) => (
                      <Block key={r.line} className="px-3.5 py-2.5">
                        <p className="text-muted-foreground text-xs leading-relaxed">
                          {r.reason}
                        </p>
                        <p className="text-muted-foreground/70 truncate font-mono text-[10px]">
                          {r.line}
                        </p>
                      </Block>
                    ))}
                  </BlockStack>
                </div>
              )}
            </div>
          )}
          {incoming.kind === "ssh-private" && (
            /* Same shape as the CRX note below, for the same reason: the
               facts card has nothing to show for a key whose fingerprint
               is only recovered inside the protect step (it may still be
               passphrase-encrypted, and it is never parsed outside
               wasm). */
            <p className="text-muted-foreground text-xs">
              {t("import_ssh_private_note")}
            </p>
          )}
          {incoming.kind === "crx" && (
            /* The facts card has nothing to show for a bare RSA PEM, so
               say in words what was detected -- otherwise this preview is
               a name and a chip. */
            <p className="text-muted-foreground text-xs">
              {t("import_crx_note")}
            </p>
          )}
        </KeyPreviewBody>
      </div>

      <div className="space-y-2 p-3">
        {/* Says why there's no Import button. The reason itself is
              already spelled out by the banner above, so don't repeat it
              here -- two red paragraphs read as two problems. */}
        {(error ?? incoming.status === "rejected") && (
          <p className="text-destructive text-xs" role="alert">
            {/* `rejection` is the classifier's own words for WHY this key
                is unusable ("expired on ...", "revoked"). It was carried
                on IncomingKey and never read, so every refusal read as
                the same generic sentence. */}
            {error ?? incoming.rejection ?? t("import_rejected_generic")}
          </p>
        )}
        {canConfirm ? (
          <Button
            className="w-full"
            onClick={onConfirm}
            disabled={busy}
            autoFocus
            // The button is autofocused, so Return already activates it
            // -- but nothing said so, and a keyboard user only found out
            // by trying. The chip is the affordance for a behaviour that
            // already existed. `aria-keyshortcuts` carries it for screen
            // readers; `Kbd` itself is aria-hidden and decorative.
            aria-keyshortcuts="Enter"
          >
            <span className="flex w-full items-center justify-center gap-2">
              {busy
                ? t("import_importing")
                : grouping
                  ? grouping.name.trim()
                    ? t("import_as_one_contact")
                    : tn("import_n_contacts", grouping.separateCount)
                  : actionLabel(incoming)}
              {!busy && (
                <Kbd shortcut={{ key: "Enter" }} className="opacity-70" />
              )}
            </span>
          </Button>
        ) : incoming.status === "duplicate" && onReveal ? (
          // Nothing to write, but the useful action isn't "Done" -- it's
          // showing the user where the key they just handed us already
          // lives.
          <Button className="w-full" onClick={onReveal} autoFocus>
            {t("import_reveal")}
          </Button>
        ) : (
          // Unusable: there is genuinely nothing to do but leave.
          <Button variant="outline" className="w-full" onClick={onDone}>
            {t("common_done")}
          </Button>
        )}
      </div>
    </div>
  );
}

/** Standalone panel around the preview -- used by the dev-only import
 *  flow harness, which has no surrounding import flow to live in. */
export function ImportPreviewPage({
  incoming,
  onConfirm,
  onBack,
}: {
  incoming: IncomingKey;
  onConfirm?: () => void;
  onBack: () => void;
}) {
  const { entered, close } = useSlideOver(onBack);
  return (
    <SlideOverPanel
      entered={entered}
      ariaLabel={t("import_panel_aria_with_id", { keyid: incoming.keyId })}
      onDismiss={close}
    >
      <SlideOverHeader
        title={
          incoming.status === "update"
            ? t("import_title_update")
            : t("import_title")
        }
        onBack={close}
      />
      <ImportPreview incoming={incoming} onConfirm={onConfirm} onDone={close} />
    </SlideOverPanel>
  );
}
