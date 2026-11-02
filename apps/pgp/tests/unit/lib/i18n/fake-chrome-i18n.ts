import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * TEST DOUBLE for `chrome.i18n` (vitest setupFiles), backed by the BUILT
 * `public/_locales/en/messages.json`. Never imported by shipped code.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const EN = JSON.parse(
  readFileSync(
    join(
      HERE,
      "..",
      "..",
      "..",
      "..",
      "public",
      "_locales",
      "en",
      "messages.json",
    ),
    "utf8",
  ),
) as Partial<
  Record<
    string,
    { message: string; placeholders?: Record<string, { content: string }> }
  >
>;

function getMessage(key: string, substitutions?: string | string[]): string {
  const entry = EN[key];
  if (!entry) return "";
  const subs = Array.isArray(substitutions)
    ? substitutions
    : substitutions === undefined
      ? []
      : [substitutions];
  let out = entry.message;
  if (entry.placeholders) {
    for (const [name, { content }] of Object.entries(entry.placeholders)) {
      const idx = Number(content.slice(1)) - 1;
      out = out.replaceAll(`$${name}$`, subs[idx] ?? "");
    }
  }
  return out.replace(/\$(\d)/g, (_, n: string) => subs[Number(n) - 1] ?? "");
}

interface FakeI18n {
  getMessage: typeof getMessage;
  getUILanguage: () => string;
}
const g = globalThis as { chrome?: { i18n?: FakeI18n } };
g.chrome ??= {};
g.chrome.i18n ??= { getMessage, getUILanguage: () => "en" };
