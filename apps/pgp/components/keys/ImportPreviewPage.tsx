import { CheckCircleIcon, RefreshCwIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";
import { Kbd } from "@amibeingpwned/ui/kbd";

import type { IncomingKey, KeyKind } from "../../lib/import/types";
import type { KeyPreviewChip } from "./KeyPreviewBody";
import { t, tn } from "../../lib/i18n";
import { formatDate } from "../../lib/i18n/format";
import { isPublicKind } from "../../lib/import/types";
import { parseUserId } from "../../lib/utils/key-naming";
import { INPUT_CLASS } from "../../lib/utils/styles";
import {
  SlideOverHeader,
  SlideOverPanel,
  useSlideOver,
} from "../shared/SlideOver";
import { pgpKeyFacts, sshGroupKeyFacts, sshKeyFacts } from "./key-facts";
import { KeyPreviewBody } from "./KeyPreviewBody";

/**
 * The key you're about to import, shown before anything is stored: who it
 * belongs to, its fingerprint, and -- the question the old paste box never
 * answered -- whether you already have it.
 *
 * Deliberately the same body as the key details page (KeyPreviewBody), so
 * "what I saw before importing" and "what I see afterwards" are the same
 * screen. Armor is never rendered here; a private key's secret material
 * never even reaches this component (see IncomingKey.publicArmored).
 */

/** Only exceptions earn screen space -- a plain new key gets no strip at
 *  all, the same way a healthy key gets no health banner. The primary
 *  button ("Import"/"Update") carries the New case on its own.
 *
 *  A rejected key gets no strip either: KeyPreviewBody's health banner
 *  already explains, in the same words, why the key is unusable, and the
 *  reason repeats above the footer where the missing Import button is.
 *  Two identical red boxes read as two different problems. */
function ImportStatusStrip({ incoming }: { incoming: IncomingKey }) {
  const { status, changes, existingAddedAt } = incoming;
  if (status === "new" || status === "rejected") return null;

  const added = existingAddedAt != null ? formatDate(existingAddedAt) : null;

  if (status === "duplicate") {
    return (
      <div className="rounded-md border border-green-500/40 bg-green-500/10 p-2.5">
        <p className="flex items-center gap-1.5 text-xs font-medium text-green-400">
          <CheckCircleIcon className="h-3.5 w-3.5 shrink-0" />
          {t("import_status_duplicate")}
        </p>
        {added && (
          <p className="text-muted-foreground mt-1 pl-5 text-xs">
            {t("import_status_duplicate_added", { date: added })}
          </p>
        )}
      </div>
    );
  }

  // Only "update" reaches here: "new"/"rejected" returned above, and
  // "duplicate" is handled by the branch before this one.
  return (
    <div className="rounded-md border border-blue-500/40 bg-blue-500/10 p-2.5">
      <p className="flex items-center gap-1.5 text-xs font-medium text-blue-400">
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
    </div>
  );
}

/** Primary button wording: it should say what will happen to YOUR keys,
 *  not what kind of object this is. */
function actionLabel(incoming: IncomingKey): string {
  // A secret half doesn't import from here: the protect step comes next,
  // so the button says so rather than promising to import.
  if (!isPublicKind(incoming.kind)) {
    // Replacing a stored private key also discards its protection (and
    // any passkey binding), which re-dropping a public key can't undo --
    // so this one says exactly what it does.
    return incoming.status === "update"
      ? t("import_action_replace_stored")
      : t("common_continue");
  }
  return incoming.status === "update"
    ? t("import_action_update_contact")
    : t("import_action_import_contact");
}

/**
 * The one chip that says what this key IS, per kind.
 *
 * A Record rather than a ternary chain: adding a kind to
 * {@link KeyKind} is then a type error here until it says what it looks
 * like, instead of silently falling through to whatever the chain's last
 * branch happened to be ("Public key", which an OpenSSH private key
 * container very much is not).
 */
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

/** The algorithm of an SSH recipient line, which is simply its first
 *  token (`ssh-ed25519 AAAA...`). Read off the line rather than carried
 *  on IncomingKey: `publicArmored` IS the canonical line wasm returned,
 *  so this can't disagree with what gets stored. */
function sshAlgorithm(recipientLine: string): string {
  return recipientLine.trim().split(/\s+/)[0] ?? "";
}

interface ImportPreviewProps {
  incoming: IncomingKey;
  /** Confirm: import a public key, or step on to protection for a
   *  private one. Absent for duplicates/rejects, which have nothing to do. */
  onConfirm?: () => void;
  /** Dismiss the whole flow (the footer's only action for a key that
   *  can't be imported at all). */
  onDone: () => void;
  /** Take the user to this key where it already lives, highlighted. The
   *  action for an already-imported key: there is nothing to write, but
   *  "where is it, then?" is the obvious next question. */
  onReveal?: () => void;
  /** True while the import is running. */
  busy?: boolean;
  error?: string | null;
  /**
   * Present when this preview is OFFERING to file several pasted keys as
   * one contact rather than several.
   *
   * A person's keys rarely agree about who they belong to -- three
   * self-hosted `.pub` files can say `alice@laptop`, `alice@desktop` and
   * nothing at all -- and nothing in the text says they are one person,
   * so the import must not decide it (see `sharedComment`). Blank is
   * therefore the default and means "import them separately", which is
   * what the button then says; a name means one contact called that.
   */
  grouping?: {
    name: string;
    onNameChange: (name: string) => void;
    /** How many contacts a blank name produces. */
    separateCount: number;
  };
}

/** The preview's content and footer, without a panel of its own, so the
 *  import flow can show it as one step among several (source → preview →
 *  protect) rather than stacking slide-overs. */
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
      <div className="flex-1 space-y-4 overflow-y-auto p-3">
        <KeyPreviewBody
          name={name}
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
              <label className="text-muted-foreground mb-1 block text-xs">
                {t("import_group_label")}{" "}
                <span className="text-muted-foreground/60">
                  {t("import_optional")}
                </span>
              </label>
              <input
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
                className={INPUT_CLASS}
              />
              <p className="text-muted-foreground mt-1 text-[11px]">
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
                  <p className="text-xs font-medium text-amber-400">
                    {tn(
                      "import_github_rejected_heading",
                      incoming.group.rejected.length,
                    )}
                  </p>
                  {incoming.group.rejected.map((r) => (
                    <div
                      key={r.line}
                      className="border-l-2 border-amber-500/60 pl-2.5"
                    >
                      <p className="text-muted-foreground text-xs leading-relaxed">
                        {r.reason}
                      </p>
                      <p className="text-muted-foreground/70 truncate font-mono text-[10px]">
                        {r.line}
                      </p>
                    </div>
                  ))}
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

      <div className="border-border space-y-2 border-t p-3">
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
