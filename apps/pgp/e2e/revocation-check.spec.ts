import type { BrowserContext, Page } from "@playwright/test";

import { expect, test } from "./fixtures";
import {
  goToKeys,
  importContact,
  onboardWithPasswordSkipKey,
  readContacts,
  setKeyDiscovery,
} from "./helpers";
import { OTHER, SAM_BEFORE, SAM_REVOKED } from "./revocation-keys";

/**
 * "Check for revocation" on a contact's menu, end to end.
 *
 * A revocation only helps if it reaches you, and nothing pushes it, so
 * the menu asks keys.openpgp.org by fingerprint. What these pin: a
 * revoked answer revokes the STORED contact (and survives a reload,
 * because it is in the store), a clean answer says so, and the item is
 * not offered with key discovery off -- it is a network request.
 *
 * `context.route()` stands in for the keyserver, as in
 * `keyserver-import.spec.ts`.
 */

const PASSWORD = "correct horse battery staple";

async function stubKeyserver(
  context: BrowserContext,
  answer: { status: number; body: string },
): Promise<{ paths: () => string[] }> {
  const paths: string[] = [];
  await context.route("https://keys.openpgp.org/vks/v1/*/*", async (route) => {
    paths.push(new URL(route.request().url()).pathname);
    await route.fulfill({
      status: answer.status,
      contentType: answer.status === 200 ? "application/pgp-keys" : "text/html",
      body: answer.body,
    });
  });
  return { paths: () => paths };
}

async function checkSam(panel: Page): Promise<void> {
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Contact options" }).click();
  await panel.getByRole("menuitem", { name: "Check for revocation" }).click();
}

test("a revoked answer revokes the stored contact", async ({
  context,
  panel,
}) => {
  const keyserver = await stubKeyserver(context, {
    status: 200,
    body: SAM_REVOKED,
  });
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await importContact(panel, SAM_BEFORE);

  await checkSam(panel);

  await expect(panel.getByText(/has revoked this key/)).toBeVisible();
  await expect(panel.getByText("Revoked", { exact: true })).toBeVisible();
  // Asked by fingerprint: the one query that can't return someone else.
  expect(keyserver.paths()).toEqual([
    expect.stringMatching(/^\/vks\/v1\/by-fingerprint\/[0-9A-F]{40}$/),
  ]);

  const [stored] = await readContacts(panel);
  expect(stored).toMatchObject({ revoked: true, usableForEncryption: false });

  // Nothing left to learn about a revoked key: the item goes away.
  await panel.getByRole("button", { name: "Contact options" }).click();
  await expect(
    panel.getByRole("menuitem", { name: "Check for revocation" }),
  ).toHaveCount(0);
});

test("a clean answer says the key is not revoked", async ({
  context,
  panel,
}) => {
  await stubKeyserver(context, { status: 200, body: SAM_BEFORE });
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await importContact(panel, SAM_BEFORE);

  await checkSam(panel);

  await expect(
    panel.getByText(/key is not revoked on keys\.openpgp\.org/),
  ).toBeVisible();
  const [stored] = await readContacts(panel);
  expect(stored.revoked).toBeUndefined();
});

test("a key the keyserver doesn't publish is said plainly", async ({
  context,
  panel,
}) => {
  await stubKeyserver(context, { status: 404, body: "<p>not found</p>" });
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await importContact(panel, SAM_BEFORE);

  await checkSam(panel);

  await expect(
    panel.getByText(/doesn't publish .* key, so it can't be checked there/),
  ).toBeVisible();
});

test("an answer with someone else's key changes nothing", async ({
  context,
  panel,
}) => {
  await stubKeyserver(context, { status: 200, body: OTHER });
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await importContact(panel, SAM_BEFORE);
  const [before] = await readContacts(panel);

  await checkSam(panel);

  await expect(
    panel.getByText(/returned a key that doesn't match/),
  ).toBeVisible();
  const after = await readContacts(panel);
  expect(after).toHaveLength(1);
  expect(after[0].armoredPublicKey).toBe(before.armoredPublicKey);
});

test("the key details page offers the check, and shows the answer in place", async ({
  context,
  panel,
}) => {
  await stubKeyserver(context, { status: 200, body: SAM_REVOKED });
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await importContact(panel, SAM_BEFORE);

  await goToKeys(panel);
  await panel.getByRole("button", { name: "Key details" }).last().click();
  const details = panel.getByRole("region", { name: /^Key details for/ });
  await details.getByRole("button", { name: "Check for revocation" }).click();

  await expect(panel.getByText(/has revoked this key/)).toBeVisible();
  // Still on the page: it reads the live contact, so the revocation
  // shows here without leaving and coming back.
  await expect(details.getByText("This key has been revoked")).toBeVisible();
  await expect(
    details.getByRole("button", { name: "Check for revocation" }),
  ).toHaveCount(0);
  // Nor offered as a recipient any more.
  await expect(details.getByRole("button", { name: "Encrypt to" })).toHaveCount(
    0,
  );
});

test("with key discovery off, the check is not offered", async ({ panel }) => {
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await importContact(panel, SAM_BEFORE);
  await setKeyDiscovery(panel, false);

  await goToKeys(panel);
  await panel.getByRole("button", { name: "Contact options" }).click();
  await expect(
    panel.getByRole("menuitem", { name: "Check for revocation" }),
  ).toHaveCount(0);
});
