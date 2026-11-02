import { useSyncExternalStore } from "react";

import type { PgpPreferences } from "../lib/storage/preferences";
import type { UpdateOptions } from "../lib/storage/preferences-store";
import { t } from "../lib/i18n";
import { preferencesStore } from "../lib/storage/preferences-store";
import { toast } from "../lib/toast";

/** The panel's preferences, re-rendering when any of them changes. */
export function usePreferences(): PgpPreferences {
  return useSyncExternalStore(preferencesStore.subscribe, preferencesStore.get);
}

/**
 * Save a change the user just made. A save that rejects (the stored
 * settings would not open, and nothing proves this session may replace
 * them) must say so rather than be dropped: the next unlock would read
 * the old value back. The store puts the stored value back on screen.
 * Never rejects.
 */
export async function savePreference(
  patch: Partial<PgpPreferences>,
  opts?: UpdateOptions,
): Promise<void> {
  try {
    await preferencesStore.update(patch, opts);
  } catch {
    toast.error(t("shared_settings_save_failed"), {
      id: "settings-save-failed",
    });
  }
}
