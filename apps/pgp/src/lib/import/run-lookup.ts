import { t } from "~/lib/i18n";
import type {
  GithubKeysRequest,
  GithubKeysResponse,
  KeyserverKeyRequest,
  KeyserverKeyResponse,
} from "~/lib/messages";
import type { PublicContactKey } from "~/lib/storage/contacts";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import { githubFailureCopy, prepareGithubImport } from "./github";
import {
  KEYSERVER_HOST,
  keyserverFailureCopy,
  prepareKeyserverImport,
} from "./keyserver";
import type { Lookup } from "./lookup";
import { storedKeysFrom } from "./stored-keys";
import type { IncomingKey } from "./types";

export type LookupOutcome =
  | {
      kind: "keys";
      keys: IncomingKey[];
      /** Toasts to show, each with a stable id so a re-run never stacks. */
      warnings: { id: string; message: string }[];
    }
  | { kind: "notice"; message: string }
  | { kind: "error"; message: string };

const unreachable = (): LookupOutcome => ({
  kind: "error",
  message: t("import_worker_unreachable"),
});

/**
 * Run a classified lookup through the worker, which owns the only fetch;
 * what it forwards is untrusted until the engine parses it here.
 */
export async function runKeyLookup(
  lookup: Lookup,
  held: { own: ProtectedKeyBlob[]; contacts: PublicContactKey[] },
): Promise<LookupOutcome> {
  if (lookup.target === "github") {
    const response = await chrome.runtime.sendMessage<
      GithubKeysRequest,
      GithubKeysResponse | undefined
    >({ type: "GITHUB_KEYS_REQUEST", username: lookup.username });
    if (!response) return unreachable();
    if (!response.ok) {
      const copy = githubFailureCopy(
        response.error,
        lookup.username,
        response.resetAt,
      );
      return {
        kind: copy.tone === "notice" ? "notice" : "error",
        message: copy.message,
      };
    }
    const prepared = await prepareGithubImport(
      response.username,
      response.lines,
      held,
      { omitted: response.omitted },
    );
    return { kind: "keys", keys: prepared.keys, warnings: [] };
  }

  const response = await chrome.runtime.sendMessage<
    KeyserverKeyRequest,
    KeyserverKeyResponse | undefined
  >({ type: "KEYSERVER_KEY_REQUEST", query: lookup.query });
  if (!response) return unreachable();
  if (!response.ok) {
    const copy = keyserverFailureCopy(
      response.error,
      lookup.query,
      response.retryAt,
    );
    return {
      kind: copy.tone === "notice" ? "notice" : "error",
      message: copy.message,
    };
  }
  const prepared = await prepareKeyserverImport(
    response.query,
    response.armored,
    storedKeysFrom(held.own, held.contacts),
  );
  if (prepared.unparseable || prepared.keys.length === 0) {
    return {
      kind: "error",
      message: t("import_keyserver_not_a_key", { host: KEYSERVER_HOST }),
    };
  }
  const key = prepared.keys[0];
  const warnings: { id: string; message: string }[] = [];
  if ((response.omitted ?? 0) > 0) {
    warnings.push({
      id: "keyserver-multiple-keys",
      message: t("import_keyserver_multiple_keys", { host: KEYSERVER_HOST }),
    });
  }
  if (key.securityWarning) {
    warnings.push({ id: "import-key-warning", message: key.securityWarning });
  }
  return { kind: "keys", keys: [key], warnings };
}
