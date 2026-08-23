#!/usr/bin/env node
// ──────────────────────────────────────────────────────────────────────
// update-badges.mjs — write the README's badge row from MEASURED values
//
// Badges are a claim about the project made in the first screenful of
// the README, which is exactly where a stale number does the most
// damage. So none of these are typed by hand: each is read from an
// artifact produced by the suite it describes, and `--check` re-reads
// them and fails if the README has drifted. CI runs `--check` after the
// tests, so a badge cannot quietly keep saying 74% once it isn't.
//
// WHAT THE COVERAGE BADGE DELIBERATELY DOES NOT SAY. It is labelled
// "lib coverage", not "coverage". Vitest runs without a DOM, so it is
// the wrong instrument for components/ and entrypoints/ -- those are
// covered by the Playwright suite against the real built extension, and
// anything touching key material is covered by the Rust tests in
// gpg-wasm/. Pointing v8 at the whole tree would produce a smaller
// number attached to a much larger claim: honest-looking, and wrong in
// both directions at once. The e2e and unit counts sit beside it so the
// scope of each figure is visible rather than implied.
// ──────────────────────────────────────────────────────────────────────

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const appDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(appDir, "../..");
const readmePath = path.join(repoRoot, "README.md");

const START = "<!-- badges:start -->";
const END = "<!-- badges:end -->";

/** shields.io colour ramp. Thresholds are the conventional ones so the
 *  colour means the same thing here as on every other project. */
function coverageColour(pct) {
  if (pct >= 90) return "brightgreen";
  if (pct >= 80) return "green";
  if (pct >= 70) return "yellowgreen";
  if (pct >= 60) return "yellow";
  if (pct >= 50) return "orange";
  return "red";
}

/** shields.io reads `-` as its field separator, so a literal one in a
 *  label has to be doubled, and spaces become underscores. The `%` on a
 *  coverage figure has to be percent-encoded LAST, or it would escape
 *  the escapes introduced above. */
function shieldText(text) {
  return String(text)
    .replace(/-/g, "--")
    .replace(/ /g, "_")
    .replace(/%/g, "%25");
}

function badge(label, message, colour, link) {
  const url = `https://img.shields.io/badge/${shieldText(label)}-${shieldText(message)}-${colour}`;
  const img = `<img src="${url}" alt="${label}: ${message}" />`;
  return link ? `<a href="${link}">${img}</a>` : img;
}

function run(command, args) {
  return execFileSync(command, args, {
    cwd: appDir,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });
}

function libCoveragePct() {
  const summaryPath = path.join(appDir, "coverage/coverage-summary.json");
  let raw;
  try {
    raw = readFileSync(summaryPath, "utf8");
  } catch {
    throw new Error(
      `No coverage summary at ${summaryPath}. Run \`pnpm coverage\` first.`,
    );
  }
  // Lines, not statements: it is the figure people picture when they
  // read "coverage", and picking the flattering one of the four would
  // make the badge a sales pitch.
  return JSON.parse(raw).total.lines.pct;
}

function unitTestCount() {
  // `vitest list` collects without executing -- a count, not a re-run.
  const lines = run("npx", ["vitest", "list"]).split("\n");
  return lines.filter((line) => line.includes(" > ")).length;
}

function e2eTestCount() {
  const listing = run("npx", ["playwright", "test", "--list", "--reporter=line"]);
  const match = /Total:\s+(\d+)\s+tests?/.exec(listing);
  if (!match) throw new Error("Could not read a test total from Playwright.");
  return Number(match[1]);
}

function buildBadgeRow() {
  const pct = libCoveragePct();
  const rounded = Math.round(pct * 10) / 10;
  // The CI badge is GitHub's own live workflow SVG, not a shields
  // snapshot: build status is the one figure here that changes without
  // anyone running this script, so it must not be a stored value.
  const ci =
    '<a href="https://github.com/Am-I-Being-Pwned/PGP-Tools/actions/workflows/ci.yml">' +
    '<img src="https://github.com/Am-I-Being-Pwned/PGP-Tools/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI" />' +
    "</a>";
  return [
    ci,
    badge("lib coverage", `${rounded}%`, coverageColour(pct)),
    badge("unit tests", unitTestCount(), "blue"),
    badge("e2e tests", e2eTestCount(), "blue"),
  ].join("\n  ");
}

const readme = readFileSync(readmePath, "utf8");
const start = readme.indexOf(START);
const end = readme.indexOf(END);
if (start === -1 || end === -1 || end < start) {
  throw new Error(`README.md is missing the ${START} / ${END} markers.`);
}

const row = buildBadgeRow();
const block = `${START}\n<p align="center">\n  ${row}\n</p>\n${END}`;
const updated = readme.slice(0, start) + block + readme.slice(end + END.length);

if (process.argv.includes("--check")) {
  if (updated !== readme) {
    console.error(
      "README badges are out of date. Run `pnpm badges` and commit the result.",
    );
    process.exit(1);
  }
  console.log("✅ README badges match the measured values.");
} else {
  writeFileSync(readmePath, updated);
  console.log("✅ README badges updated.");
}
