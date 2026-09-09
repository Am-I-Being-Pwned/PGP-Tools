#!/usr/bin/env node
/**
 * Keep every target phrase inside the store's usable repetition window.
 *
 * A phrase used once anywhere in a description retrieves its own listing about
 * 2% of the time; used twice, 65%. Below two mentions a phrase is invisible.
 * The spam policy flags repetition above five. Two to five is the whole window.
 *
 *   node scripts/check-listing-mentions.mjs [STORE-LISTING.md]
 */
import { readFileSync } from "node:fs";

const FLOOR = 2;
const CEILING = 5;

const PHRASES = [
  "openpgp", "gpg", "message encryption", "email security", "file encryption",
  "digital signature", "key management", "privacy", "security",
];

const path = process.argv[2] ?? "STORE-LISTING.md";
const text = readFileSync(path, "utf8");

const block = /## Detailed description \(English\)[\s\S]*?```text\n([\s\S]*?)```/.exec(text);
if (!block) {
  console.error(`no \`\`\`text detailed-description block found in ${path}`);
  process.exit(1);
}
const body = block[1].toLowerCase();

const count = (needle) => body.split(needle).length - 1;
const failures = [];

for (const phrase of PHRASES) {
  const n = count(phrase);
  if (n < FLOOR) {
    failures.push([phrase, n, `below the ${FLOOR}-mention floor, invisible to the index`]);
  } else if (n > CEILING) {
    failures.push([phrase, n, `above ${CEILING}, invites a spam review`]);
  }
  console.log(`${phrase.padEnd(22)} ${n}`);
}

if (failures.length) {
  console.log("");
  for (const [phrase, n, why] of failures) {
    console.log(`FAIL ${phrase.padEnd(22)} ${n}: ${why}`);
  }
  process.exit(1);
}
console.log(`\nall ${PHRASES.length} phrases inside the ${FLOOR}-${CEILING} window`);
