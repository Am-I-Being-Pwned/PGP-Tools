#!/usr/bin/env node
// update-badges.mjs — write the README's badge row from MEASURED values.
// Each badge is read from its suite's artifact; `--check` (run in CI) fails on
// drift. Coverage is labelled "lib coverage" on purpose: vitest has no DOM, so
// src/components/entrypoints are covered by Playwright and key material by the
// Rust tests — a whole-tree figure would be a smaller number making a bigger claim.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const appDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(appDir, "../..");
const readmePath = path.join(repoRoot, "README.md");

const CHROME_ID = "pgpcdgggohpbombhkffjoiiafdlfcpgp";
const CHROME_LISTING = `https://chromewebstore.google.com/detail/pgp-tools-encrypt-decrypt/${CHROME_ID}`;

const START = "<!-- badges:start -->";
const END = "<!-- badges:end -->";

/** shields.io colour ramp, conventional thresholds. */
function coverageColour(pct) {
  if (pct >= 90) return "brightgreen";
  if (pct >= 80) return "green";
  if (pct >= 70) return "yellowgreen";
  if (pct >= 60) return "yellow";
  if (pct >= 50) return "orange";
  return "red";
}

/** shields.io escaping: `-` doubled, spaces → `_`, `%` encoded LAST so it
 *  doesn't escape the earlier escapes. */
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
  // Lines, not the most flattering of the four metrics.
  return JSON.parse(raw).total.lines.pct;
}

function unitTestCount() {
  // From the JSON report `pnpm test` writes. Not `vitest list`: it collapses
  // each `it.each` to one line and undercounts by hundreds.
  const resultsPath = path.join(appDir, "coverage/test-results.json");
  let raw;
  try {
    raw = readFileSync(resultsPath, "utf8");
  } catch {
    throw new Error(
      `No test results at ${resultsPath}. Run \`pnpm test\` first.`,
    );
  }
  return JSON.parse(raw).numTotalTests;
}

function e2eTestCount() {
  const listing = run("npx", [
    "playwright",
    "test",
    "--list",
    "--reporter=line",
  ]);
  const match = /Total:\s+(\d+)\s+tests?/.exec(listing);
  if (!match) throw new Error("Could not read a test total from Playwright.");
  return Number(match[1]);
}

function buildBadgeRow() {
  const pct = libCoveragePct();
  const rounded = Math.round(pct * 10) / 10;
  // Live workflow SVG: build status changes without a commit.
  const ci =
    '<a href="https://github.com/Am-I-Being-Pwned/PGP-Tools/actions/workflows/ci.yml">' +
    '<img src="https://github.com/Am-I-Being-Pwned/PGP-Tools/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI" />' +
    "</a>";
  // Live endpoints for the same reason. Edge is omitted: a "0 users" badge
  // reads as a verdict on the extension rather than on the listing's age.
  const store = [
    `<a href="${CHROME_LISTING}"><img src="https://img.shields.io/chrome-web-store/users/${CHROME_ID}" alt="Chrome Web Store users" /></a>`,
    `<a href="${CHROME_LISTING}"><img src="https://img.shields.io/chrome-web-store/rating/${CHROME_ID}" alt="Chrome Web Store rating" /></a>`,
  ];
  return [
    ci,
    ...store,
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
