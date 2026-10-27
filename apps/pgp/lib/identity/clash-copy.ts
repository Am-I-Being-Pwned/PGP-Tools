/**
 * The words for a clash between two contacts (see `contactClashes`), in
 * one place: the contact card, the recipient picker and the details page
 * each showed it with their own copy of the same ternary, and a new kind
 * of clash had to be added to all of them.
 */

import type { IdentityConflict, IdentityHolder } from "./binding";
import { t } from "../i18n";
import { parseUserId } from "../utils/key-naming";
import { displayKeyId } from "./binding";

/** The holder as the user knows it: by the name they gave it, when they
 *  did (a comment-less SSH key has no other). */
export function clashHolderArgs(holder: IdentityHolder): {
  name: string;
  keyid: string;
} {
  return {
    name: holder.alias ?? parseUserId(holder.userIds[0] ?? "").name,
    keyid: displayKeyId(holder.keyId),
  };
}

/** The short pill a clashing contact wears. */
export function clashPillLabel(clash: IdentityConflict): string {
  if (clash.kind === "address")
    return clash.lookalike
      ? t("keys_contact_lookalike_address")
      : t("keys_contact_same_address");
  return clash.sameName
    ? t("keys_contact_same_name_plain")
    : t("keys_contact_same_name");
}

/** What the clash is, against one holder: the pill's hover text, and a
 *  line of the details page's note. */
export function clashSentence(
  clash: IdentityConflict,
  holder: IdentityHolder = clash.holders[0],
): string {
  const args = clashHolderArgs(holder);
  if (clash.kind === "address")
    return clash.lookalike
      ? t("keys_contact_lookalike_address_title", args)
      : t("keys_contact_same_address_title", args);
  return clash.sameName
    ? t("keys_contact_same_name_plain_title", args)
    : t("keys_contact_same_name_title", args);
}
