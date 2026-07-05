import type { BrowserContext, Page } from "@playwright/test";

/**
 * Install a virtual WebAuthn authenticator that supports the PRF
 * extension, so the passkey master-protection flow can run unattended.
 *
 * `automaticPresenceSimulation` + `isUserVerified` make every ceremony
 * (create / get) succeed without a real user gesture or biometric.
 * `hasPrf` enables the hmac-secret extension the app derives its key
 * from. It's a resident key (the app requires `residentKey: required`).
 */
export async function addPrfAuthenticator(
  context: BrowserContext,
  page: Page,
): Promise<void> {
  const client = await context.newCDPSession(page);
  await client.send("WebAuthn.enable");
  await client.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      automaticPresenceSimulation: true,
      isUserVerified: true,
      // `hasPrf` enables the hmac-secret extension but isn't in every
      // bundled CDP typings version -- inject it without a type error.
      ...({ hasPrf: true } as object),
    },
  });
}
