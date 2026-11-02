/** TEST-ONLY. Imported exclusively from `*.test.ts`. */

import type { ActionCtx } from "~/lib/actions/types";

/** A ctx where nothing is loaded and nothing is possible. */
export function fakeCtx(overrides: Partial<ActionCtx> = {}): ActionCtx {
  const noop = () => undefined;
  return {
    tab: "workspace",
    mode: "encrypt",
    hasInput: false,
    canEncrypt: true,
    encryptEngine: "pgp",
    hasOutput: false,
    hasDownload: false,
    masterUnlocked: true,
    historyEnabled: false,
    encryptToSelf: false,
    alsoSign: false,
    neverCacheKeys: false,
    counts: { ownKeys: 0, contacts: 0 },
    result: { canTranslate: false, readingLanguage: "en", canReply: false },
    compose: { canEdit: true, translateEnabled: true, translateTarget: null },
    navigation: {
      setTab: noop,
      openHistory: noop,
      openGenerate: noop,
      openImport: noop,
      setMode: noop,
      openSecurityPresets: noop,
    },
    ops: {
      execute: noop,
      clearInput: noop,
      copyOutput: noop,
      downloadOutput: noop,
      lockNow: noop,
      toggleEncryptToSelf: noop,
      toggleAlsoSign: noop,
      toggleSaveToHistory: noop,
      applyStyle: noop,
      openFind: noop,
      translateTo: noop,
      translateOutput: noop,
      reply: noop,
    },
    ...overrides,
  };
}
