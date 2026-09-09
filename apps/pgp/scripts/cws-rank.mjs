#!/usr/bin/env node
/**
 * Where PGP Tools places in Chrome Web Store search, for a list of targets.
 *
 * Store search is deterministic for anonymous queries -- the same query returns
 * the same results -- so this is a baseline rather than a sample. It reads the
 * server-rendered SERP, which is the first page only, so a miss means "not in
 * the top ~10", not "not ranked at all".
 *
 *   node scripts/cws-rank.mjs                    # the tracked list
 *   node scripts/cws-rank.mjs "gpg" "openpgp"    # ad-hoc
 */
const EXTENSION_ID = "pgpcdgggohpbombhkffjoiiafdlfcpgp";
const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

const KEYWORDS = [
  "pgp", "pgp tools", "gpg", "openpgp", "gnupg",
  "encrypt", "decrypt", "encryption", "encrypt message", "encrypt text",
  "message encryption", "pgp encryption", "pgp key", "public key", "key manager",
  "email encryption", "encrypted email", "email security", "encrypt email",
  "digital signature", "verify signature", "sign message",
  "file encryption", "encrypt file",
  "encrypted messaging", "private messaging", "secure messaging", "secure chat",
  "privacy tools", "cryptography",
];

const ID_RE = /^[a-p]{32}$/;

async function serp(query) {
  const url =
    "https://chromewebstore.google.com/search/" +
    encodeURIComponent(query) +
    "?hl=en";
  const res = await fetch(url, {
    headers: { "User-Agent": UA, "Accept-Language": "en-US,en;q=0.9" },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const html = await res.text();

  const found = [];
  const seen = new Set();
  const walk = (node) => {
    if (!Array.isArray(node)) return;
    // A listing record: [id, icon, title, rating, ratings, ...].
    if (
      node.length > 6 &&
      typeof node[0] === "string" &&
      ID_RE.test(node[0]) &&
      typeof node[2] === "string"
    ) {
      if (!seen.has(node[0])) {
        seen.add(node[0]);
        found.push(node);
      }
      return;
    }
    for (const child of node) walk(child);
  };

  for (const m of html.matchAll(/AF_initDataCallback\((\{.*?\})\);/gs)) {
    const data = /data:(\[.*\])\s*,\s*sideChannel/s.exec(m[1]);
    if (!data) continue;
    try {
      walk(JSON.parse(data[1]));
    } catch {
      // Blocks that are not listing payloads parse as something else; skip.
    }
  }
  return found;
}

const queries = process.argv.slice(2).length ? process.argv.slice(2) : KEYWORDS;
let hits = 0;

for (const query of queries) {
  let rows;
  try {
    rows = await serp(query);
  } catch (err) {
    console.log(`${query.padEnd(24)} ERROR ${err.message}`);
    continue;
  }
  const ours = rows.findIndex((r) => r[0] === EXTENSION_ID);
  if (ours !== -1) hits += 1;
  const top = rows[0];
  console.log(
    `${query.padEnd(24)} n=${String(rows.length).padEnd(3)} us=${String(
      ours === -1 ? "-" : ours + 1,
    ).padEnd(4)} | #1 ${String(top?.[2] ?? "-").slice(0, 38).padEnd(38)} ${top?.[14] ?? ""}`,
  );
  await new Promise((r) => setTimeout(r, 1100));
}

console.log(`\nin the top 10 of ${hits}/${queries.length} tracked queries`);
