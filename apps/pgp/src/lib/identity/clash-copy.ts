// Clash copy in one place for the card, picker and details page.

import { t } from "~/lib/i18n";
import { parseUserId } from "~/lib/utils/key-naming";
import {
  displayKeyId,
  type IdentityConflict,
  type IdentityHolder,
} from "./binding";

/** By the user's name for it when set (a comment-less SSH key has no other). */
export function clashHolderArgs(holder: IdentityHolder): {
  name: string;
  keyid: string;
} {
  return {
    name: holder.alias ?? parseUserId(holder.userIds[0] ?? "").name,
    keyid: displayKeyId(holder.keyId),
  };
}

export function clashPillLabel(clash: IdentityConflict): string {
  if (clash.kind === "address")
    return clash.lookalike
      ? t("keys_contact_lookalike_address")
      : t("keys_contact_same_address");
  return clash.sameName
    ? t("keys_contact_same_name_plain")
    : t("keys_contact_same_name");
}

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
