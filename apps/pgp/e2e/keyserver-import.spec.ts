import type { BrowserContext, Page } from "@playwright/test";

import { expect, test } from "./fixtures";
import {
  goToKeys,
  onboardWithPasswordSkipKey,
  readContacts,
  setKeyDiscovery,
} from "./helpers";
import { keyBySlug } from "./keys";

/**
 * Looking a certificate up on keys.openpgp.org, end to end.
 *
 * What this spec is actually for, given `lib/keyserver/*.test.ts` already
 * covers the parsing in isolation:
 *
 *  1. THE REQUEST REACHES THE RIGHT URL FROM THE WORKER. The lookup runs
 *     in the MV3 service worker under the manifest CSP, and the CSP pins
 *     the path prefix. A unit test asserts the URL a function builds; only
 *     this one asserts that the browser lets the worker send it.
 *  2. THE ROUTING. One field serves two services, so "an address went to
 *     the keyserver" and "a bare name still went to GitHub" are properties
 *     of the shipped UI, not of `classifyLookup` alone.
 *  3. THE GATE. With `keyDiscoveryEnabled` off the field is not rendered
 *     at all -- which is the whole of what the strictest preset buys, and
 *     is exactly the kind of thing that survives a refactor as a
 *     `disabled` attribute nobody notices.
 *
 * ── Interception ─────────────────────────────────────────────────────
 * `context.route()` reaches service-worker requests in Playwright 1.61 --
 * see the long note in `github-import.spec.ts` for how that was
 * established. The stub COUNTS what it served and every test asserts the
 * count, so this spec cannot quietly pass by never having intercepted
 * anything (it would otherwise hit the real keys.openpgp.org, or fail
 * offline, and look like a product bug either way).
 */

const PASSWORD = "correct horse battery staple";
const ALICE = keyBySlug("standard");

/** Answer the VKS endpoint with `body`, in the shape the real service
 *  uses. Returns the paths it was asked for, so a test can assert WHICH
 *  endpoint the routing chose -- `by-email` and `by-fingerprint` are
 *  different disclosures, not just different URLs. */
async function stubKeyserver(
  context: BrowserContext,
  init: { status?: number; contentType?: string; body?: string } = {},
): Promise<{ paths: () => string[] }> {
  const paths: string[] = [];
  await context.route("https://keys.openpgp.org/vks/v1/*/*", async (route) => {
    paths.push(new URL(route.request().url()).pathname);
    await route.fulfill({
      status: init.status ?? 200,
      contentType: init.contentType ?? "application/pgp-keys",
      body: init.body ?? ALICE.publicKey,
    });
  });
  return { paths: () => paths };
}

/** Type `query` into the one lookup field and press the button. */
async function lookUp(panel: Page, query: string): Promise<void> {
  await goToKeys(panel);
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden();
  await panel.getByRole("button", { name: "Import Key" }).click();
  const field = panel.getByLabel(/look someone up/i);
  const button = panel.getByRole("button", { name: "Look up", exact: true });
  // Re-fill until the button goes live: a fill that lands while the
  // slide-over is still animating in is undone by the re-render behind
  // it, and `fill` asserts the value at the moment it types it. Same
  // idiom, same reason, as `github-import.spec.ts`.
  await expect
    .poll(async () => {
      await field.fill(query);
      return button.isEnabled();
    })
    .toBe(true);
  await button.click();
}

test("an address lookup imports the certificate as a contact", async ({
  context,
  panel,
}) => {
  const keyserver = await stubKeyserver(context);
  await onboardWithPasswordSkipKey(panel, PASSWORD);

  await lookUp(panel, ALICE.email);

  // The SAME preview every other import lands in -- there is no second
  // import flow for a fetched cert, which is the point of the design.
  await expect(panel.getByRole("region", { name: "Import key" })).toContainText(
    ALICE.name,
  );
  await panel.getByRole("button", { name: "Import contact" }).click();
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden();

  // The address is percent-encoded and lowercased in the path the worker
  // actually sent -- the canonical form, not the typed one.
  expect(keyserver.paths()).toEqual([
    `/vks/v1/by-email/${encodeURIComponent(ALICE.email)}`,
  ]);

  // Provenance is STORED, not merely displayed: it is the contact's
  // upsert identity, so a second lookup updates this record.
  const contacts = await readContacts(panel);
  expect(contacts).toHaveLength(1);
  // `toMatchObject`, because `fetchedAt` is a real timestamp -- its
  // presence is the point, its value is not assertable.
  expect(contacts[0].source).toMatchObject({
    type: "keyserver",
    user: ALICE.email,
  });
  expect(contacts[0].source?.fetchedAt).toBeGreaterThan(0);
  expect(contacts[0].keyId).toBe(ALICE.fingerprint);
});

test("looking the same person up twice cannot make a second contact", async ({
  context,
  panel,
}) => {
  // Asserted on the STORE, not the DOM: a duplicate record and a label
  // the panel happens to render twice look identical on screen, and only
  // one of them is a bug.
  await stubKeyserver(context);
  await onboardWithPasswordSkipKey(panel, PASSWORD);

  await lookUp(panel, ALICE.email);
  await panel.getByRole("button", { name: "Import contact" }).click();
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden();

  // Second time round the preview recognises it and offers no way to
  // import it again -- the same treatment a re-pasted cert gets.
  await lookUp(panel, ALICE.email);
  await expect(
    panel.getByRole("button", { name: "Import contact" }),
  ).toHaveCount(0);

  expect(await readContacts(panel)).toHaveLength(1);
});

test("a fingerprint goes to the fingerprint endpoint, not to GitHub", async ({
  context,
  panel,
}) => {
  // The one real ambiguity in the routing: 40 hex characters are also a
  // syntactically valid GitHub account name. If this ever regresses, the
  // symptom is a "no such account" error for a perfectly good
  // fingerprint -- and a username disclosed to GitHub instead.
  const keyserver = await stubKeyserver(context);
  await onboardWithPasswordSkipKey(panel, PASSWORD);

  await lookUp(panel, ALICE.fingerprint.toLowerCase());

  await expect(panel.getByRole("region", { name: "Import key" })).toContainText(
    ALICE.name,
  );
  expect(keyserver.paths()).toEqual([
    `/vks/v1/by-fingerprint/${ALICE.fingerprint}`,
  ]);
});

test("a missing key is a notice, not an error", async ({ context, panel }) => {
  // The service answers 404 with a text/html sentence quoting the query
  // back. Nothing failed and the user has nothing to fix, so this must
  // not land in the destructive slot -- and none of that prose may reach
  // the page.
  const keyserver = await stubKeyserver(context, {
    status: 404,
    contentType: "text/html; charset=utf-8",
    body: "No key found for email address nobody@example.com",
  });
  await onboardWithPasswordSkipKey(panel, PASSWORD);

  await lookUp(panel, "nobody@example.com");

  const notice = panel.getByRole("status").filter({ hasText: /no key/i });
  await expect(notice).toBeVisible();
  await expect(notice).toContainText(/confirmed/i);
  await expect(panel.getByRole("alert")).toHaveCount(0);
  // Our copy, not theirs.
  await expect(panel.getByText("No key found for email address")).toHaveCount(
    0,
  );
  // And the flow stays on the source step, ready for another try.
  await expect(
    panel.getByRole("button", { name: "Look up", exact: true }),
  ).toBeVisible();
  expect(keyserver.paths()).toHaveLength(1);
});

test("with key discovery off, no lookup exists to make", async ({
  context,
  panel,
}) => {
  const keyserver = await stubKeyserver(context);
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await setKeyDiscovery(panel, false);

  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();
  // ABSENT, not disabled: a greyed-out control that explains itself is
  // still an invitation, and the preset that turns this off means it.
  await expect(panel.getByLabel(/look someone up/i)).toHaveCount(0);
  await expect(
    panel.getByRole("button", { name: "Look up", exact: true }),
  ).toHaveCount(0);
  // Nothing was asked of the network on the way here.
  expect(keyserver.paths()).toHaveLength(0);

  // And turning it back on restores it -- the preference gates the UI,
  // it does not remove the feature. The slide-over has to come down
  // first: it sits over the tab strip, so a Settings click aimed through
  // it is intercepted rather than ignored.
  await panel.getByRole("button", { name: "Back" }).click();
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden();
  await setKeyDiscovery(panel, true);
  await lookUp(panel, ALICE.email);
  await expect(panel.getByRole("region", { name: "Import key" })).toContainText(
    ALICE.name,
  );
  expect(keyserver.paths()).toHaveLength(1);
});
