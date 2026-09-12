#!/usr/bin/env node
/**
 * Every locale's store name and summary must fit the store and follow the
 * keyword-first rule.
 *
 * The store indexes each locale's name as its own matchable string and ranks
 * by how much of the title the query covers, so a brand prefix on every
 * localised name is dead weight in front of the words people search for. The
 * `en` name is the exception and is pinned: it holds #1 for "pgp tools".
 *
 *   node scripts/check-locale-names.mjs
 */
import { readdirSync, readFileSync } from "node:fs";

const DIR = "public/_locales";
const NAME_MAX = 75; // Chrome Web Store hard cap.
const SUMMARY_MAX = 132; // Chrome Web Store hard cap.
const BRAND = "PGP Tools";
const EN_NAME = "PGP Tools - Encrypt, Decrypt & Sign";

const length = (s) => [...s].length;
const failures = [];

for (const locale of readdirSync(DIR).sort()) {
  const m = JSON.parse(readFileSync(`${DIR}/${locale}/messages.json`, "utf8"));
  const name = m.extName?.message ?? "";
  const summary = m.extDescription?.message ?? "";
  const fail = (why) => failures.push(`${locale}: ${why}`);

  if (!name) fail("missing extName");
  if (!summary) fail("missing extDescription");
  if (length(name) > NAME_MAX)
    fail(`name is ${length(name)} chars, cap ${NAME_MAX}`);
  if (length(summary) > SUMMARY_MAX)
    fail(`summary is ${length(summary)} chars, cap ${SUMMARY_MAX}`);
  if (/\s{2,}|^\s|\s$/.test(name)) fail("name has stray whitespace");

  if (locale === "en") {
    if (name !== EN_NAME) fail(`en name must stay "${EN_NAME}"`);
    continue;
  }
  if (locale.startsWith("en_")) {
    // English-variant locales stay brand-first, like `en`.
    if (!name.startsWith(`${BRAND} - `))
      fail(`English locales start with "${BRAND} - "`);
  } else {
    // Every other locale: native keyword phrase, then " - " and one or two
    // English tails that claim a query of their own ("X Alternative",
    // "Y Compatible"). Nominative use only; never a bare competitor name.
    if (name.startsWith(BRAND))
      fail("name starts with the brand; lead with the native keyword phrase");
    const tail = name.split(" - ")[1] ?? "";
    if (
      !/\b(Alternative|Compatible|Extension|Online|Generator|Tool|Encryption)\b/.test(
        tail,
      )
    )
      fail(
        "no English tail (Alternative / Compatible / Extension / Online / Generator / Tool / Encryption)",
      );
    if (
      /\b(Mailvelope|FlowCrypt|Gmail|Outlook|Slack|Discord|Thunderbird|Proton Mail)\b(?![^,]*\b(Alternative|Compatible)\b)/.test(
        name,
      )
    ) {
      fail("a brand name must be followed by Alternative or Compatible");
    }
  }
  if (!/OpenPGP|GPG|PGP/.test(name))
    fail("name carries no PGP/GPG/OpenPGP token");
  console.log(`${locale.padEnd(7)} ${String(length(name)).padEnd(3)} ${name}`);
}

if (failures.length) {
  console.log("");
  for (const f of failures) console.log(`FAIL ${f}`);
  process.exit(1);
}
console.log(`\nall locales pass`);
