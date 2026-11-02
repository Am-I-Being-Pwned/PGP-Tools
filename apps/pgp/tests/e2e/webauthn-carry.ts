import type { BrowserContext, CDPSession, Page } from "@playwright/test";

/**
 * Carrying a PRF-capable passkey ACROSS TWO BROWSER LAUNCHES.
 *
 * `webauthn.ts` is enough for any spec that lives inside one browser: a
 * virtual authenticator is created on a page's CDP session, the app
 * registers a credential, and everything the app needs is in memory for
 * as long as that page exists. `upgrade.spec.ts` cannot use it, because
 * the whole point of that spec is that the browser is torn down and
 * relaunched between the shipped build and the current one.
 *
 * ## What is and isn't possible, measured rather than assumed
 *
 * Chrome's virtual authenticator is scoped to the FrameTreeNode the CDP
 * session is attached to -- verified: a second tab on the same origin,
 * with no authenticator of its own, hangs forever on
 * `navigator.credentials.create`. So it does not survive the tab, let
 * alone the browser. `WebAuthn.enable` is also rejected on a
 * browser-level CDP session ("'WebAuthn.enable' wasn't found"), so there
 * is no wider scope to attach it to. And an extension reload -- the one
 * way to swap builds without relaunching Chrome -- destroys every
 * extension page, taking the tab (and the authenticator) with it.
 *
 * That leaves `WebAuthn.getCredentials` / `WebAuthn.addCredential`, and
 * they get us MOST of the way:
 *
 *  - `getCredentials` exports `credentialId`, `rpId`, the PKCS#8
 *    `privateKey`, `userHandle` and `signCount`. Feeding those to
 *    `addCredential` on a fresh authenticator in a fresh browser gives a
 *    credential that really asserts: `navigator.credentials.get` with
 *    the original id in `allowCredentials` succeeds, and the app sees a
 *    genuine `PublicKeyCredential` with the right `rawId`.
 *
 *  - It does NOT carry the hmac-secret seed. The CDP `Credential` type
 *    has no field for it (checked against the live protocol of the
 *    Chrome 149 build these tests run under: `credentialId`,
 *    `isResidentCredential`, `rpId`, `privateKey`, `userHandle`,
 *    `signCount`, `largeBlob`, `backupEligibility`, `backupState`,
 *    `userName`, `userDisplayName` -- and nothing else). Measured
 *    end to end: create a PRF credential, evaluate PRF over a fixed
 *    salt, export, relaunch, re-add, evaluate the same salt again ->
 *    `getClientExtensionResults().prf` comes back **undefined**. Not a
 *    different value: absent. There is no hmac-secret state to restore.
 *
 * So a PRF-capable credential cannot be carried across two browser
 * launches, and no amount of CDP will change that.
 *
 * ## What this module does instead, and what it therefore proves
 *
 * The authenticator is stubbed exactly at its contract and nowhere else.
 * An authenticator's entire job, from the app's point of view, is
 * "same credential + same salt -> same 32 bytes, forever". So:
 *
 *  1. In the FIRST launch, {@link installPrfRecorder} wraps
 *     `navigator.credentials.get` and records every
 *     `(credentialId, salt) -> prfOutput` the REAL virtual authenticator
 *     produced. It observes; it changes nothing.
 *  2. In the SECOND launch, the credential is restored with
 *     `addCredential`, so the ceremony itself is real, and
 *     {@link installPrfReplay} calls through to the real
 *     `navigator.credentials.get` and then patches the recorded PRF
 *     bytes onto the assertion it returns.
 *
 * Everything else is untouched and real: the master-protection record,
 * the keyring blob, the `storedSecret`, the HKDF, the AES-GCM unseal,
 * the wasm exports, and both builds' code. What is faked is one function
 * of two inputs whose only specified property is determinism.
 *
 * The replay is deliberately EXACT-MATCH and fail-closed. A lookup is
 * keyed on the credential id the app asked for and the salt bytes it
 * asked for; a miss is recorded and nothing is patched, so the app gets
 * an assertion with no PRF result and fails the way it would against an
 * authenticator that had never seen that salt. Which means the replay
 * doubles as an assertion in its own right: if the current build read a
 * different `credentialId` or a different `prfSalt` out of the 1.4.4
 * blob than 1.4.4 wrote there, it does not quietly get the right key --
 * it misses, and the test fails. See {@link readPrfRequests}.
 *
 * This is NOT a substitute for a real cross-launch PRF credential, and
 * the spec says so where it uses it. It is the strongest thing the
 * platform permits.
 */

/** The authenticator configuration, shared by both launches so the
 *  restored credential lands in an authenticator that behaves like the
 *  one it was minted in. Same options as `webauthn.ts`; duplicated
 *  rather than imported because that helper returns `void` and this one
 *  must hand back the `authenticatorId` that `getCredentials` needs. */
const PRF_AUTHENTICATOR_OPTIONS = {
  protocol: "ctap2" as const,
  transport: "internal" as const,
  hasResidentKey: true,
  hasUserVerification: true,
  automaticPresenceSimulation: true,
  isUserVerified: true,
  // `hasPrf` enables the hmac-secret extension but isn't in every
  // bundled CDP typings version -- inject it without a type error.
  ...({ hasPrf: true } as object),
};

export interface VirtualAuthenticator {
  client: CDPSession;
  authenticatorId: string;
}

/** One observed PRF evaluation. `salt` and `output` are lowercase hex;
 *  `credentialId` is base64url, as the app stores it. */
export interface PrfRecord {
  credentialId: string;
  salt: string;
  output: string;
}

/** What the app asked the authenticator for, and whether the replay had
 *  an answer. A `replayed: false` entry means the app requested a
 *  (credential, salt) pair that the shipped build never used. */
export interface PrfRequest {
  credentialId: string;
  salt: string;
  replayed: boolean;
}

/** Add a PRF-capable virtual authenticator and keep its id. */
export async function addPrfAuthenticatorWithId(
  context: BrowserContext,
  page: Page,
): Promise<VirtualAuthenticator> {
  const client = await context.newCDPSession(page);
  await client.send("WebAuthn.enable");
  const { authenticatorId } = await client.send(
    "WebAuthn.addVirtualAuthenticator",
    { options: PRF_AUTHENTICATOR_OPTIONS },
  );
  return { client, authenticatorId };
}

/** Remove the authenticator. Cheap, but the CDP session outlives the
 *  page it was opened on, so tidy it up explicitly. */
export async function removePrfAuthenticator(
  auth: VirtualAuthenticator,
): Promise<void> {
  await auth.client
    .send("WebAuthn.removeVirtualAuthenticator", {
      authenticatorId: auth.authenticatorId,
    })
    .catch(() => undefined);
  await auth.client.detach().catch(() => undefined);
}

/** Every credential the authenticator holds, in `addCredential` shape. */
export async function exportCredentials(
  auth: VirtualAuthenticator,
): Promise<unknown[]> {
  const { credentials } = await auth.client.send("WebAuthn.getCredentials", {
    authenticatorId: auth.authenticatorId,
  });
  return credentials;
}

/** Put previously exported credentials into a fresh authenticator. The
 *  assertion path works; the PRF path does not -- see the module note. */
export async function restoreCredentials(
  auth: VirtualAuthenticator,
  credentials: unknown[],
): Promise<void> {
  for (const credential of credentials) {
    await auth.client.send("WebAuthn.addCredential", {
      authenticatorId: auth.authenticatorId,
      // `credential` is round-tripped verbatim from `getCredentials`;
      // the CDP typings want the concrete struct.
      credential: credential as never,
    });
  }
}

/**
 * The shared preamble for both init scripts: hex/base64url helpers and a
 * `wrapCredentialsGet` that installs an own-property override on
 * `navigator.credentials`, shadowing the prototype method.
 */
const PRF_SHIM_PRELUDE = `
const toHex = (b) =>
  Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (s) =>
  new Uint8Array(s.match(/../g).map((h) => parseInt(h, 16)));
const toB64u = (b) =>
  btoa(String.fromCharCode(...new Uint8Array(b)))
    .replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
const saltOf = (options) => {
  const first = options && options.publicKey &&
    options.publicKey.extensions && options.publicKey.extensions.prf &&
    options.publicKey.extensions.prf.eval &&
    options.publicKey.extensions.prf.eval.first;
  return first ? toHex(first) : null;
};
`;

/**
 * Launch 1: observe. Wraps `navigator.credentials.get` and appends every
 * PRF evaluation the real authenticator performed to `window.__prfLog`.
 *
 * Must be installed before the first navigation, and it re-installs on
 * every navigation, so a panel reload keeps recording -- but the log
 * itself is per-document, so drain it with {@link drainPrfLog} before
 * reloading or closing the page.
 */
export async function installPrfRecorder(page: Page): Promise<void> {
  await page.addInitScript(`(() => {
${PRF_SHIM_PRELUDE}
  const log = [];
  Object.defineProperty(window, "__prfLog", { value: log, configurable: true });
  const container = navigator.credentials;
  const original = container.get.bind(container);
  Object.defineProperty(container, "get", {
    configurable: true,
    writable: true,
    value: async function (options) {
      const credential = await original(options);
      try {
        const salt = saltOf(options);
        if (salt && credential) {
          const results = credential.getClientExtensionResults();
          const output = results && results.prf && results.prf.results &&
            results.prf.results.first;
          if (output) {
            log.push({
              credentialId: toB64u(credential.rawId),
              salt,
              output: toHex(output),
            });
          }
        }
      } catch (e) {
        // Recording must never be able to break the app under test.
      }
      return credential;
    },
  });
})();`);
}

/** Read (and clear) what the recorder saw in the CURRENT document. */
export async function drainPrfLog(page: Page): Promise<PrfRecord[]> {
  return page.evaluate(() => {
    const log = (window as unknown as { __prfLog?: unknown[] }).__prfLog ?? [];
    const copy = log.slice() as unknown as {
      credentialId: string;
      salt: string;
      output: string;
    }[];
    log.length = 0;
    return copy;
  });
}

/**
 * Launch 2: replay. Runs the REAL ceremony against the restored
 * credential, then patches the recorded PRF output onto the assertion.
 *
 * Fail-closed: an unrecorded (credentialId, salt) pair is left
 * unpatched, so the app sees an authenticator with no PRF result. Every
 * request is logged to `window.__prfRequests` either way.
 *
 * `corrupt` flips the low bit of the first byte of every replayed
 * output. Used by the negative control: with the ceremony, the
 * credential, the salt and the stored secret all still genuine and only
 * the PRF bytes one bit wrong, nothing may open.
 */
export async function installPrfReplay(
  page: Page,
  records: PrfRecord[],
  options: { corrupt?: boolean } = {},
): Promise<void> {
  // Init scripts only accept an `arg` when the script is a FUNCTION, and
  // a function would be serialised by `toString()` -- taking the shared
  // prelude out of scope. The data is hex and base64url, so embedding it
  // as a JSON literal is both safe and simpler.
  await page.addInitScript(`((records, corrupt) => {
${PRF_SHIM_PRELUDE}
  const requests = [];
  Object.defineProperty(window, "__prfRequests", {
    value: requests,
    configurable: true,
  });
  const container = navigator.credentials;
  const original = container.get.bind(container);
  Object.defineProperty(container, "get", {
    configurable: true,
    writable: true,
    value: async function (options) {
      const salt = saltOf(options);
      // The ceremony itself is real: a restored credential asserts, a
      // missing one throws NotAllowedError exactly as it would if the
      // user had no passkey.
      const credential = await original(options);
      if (!salt || !credential) return credential;
      const id = toB64u(credential.rawId);
      const hit = records.find((r) => r.credentialId === id && r.salt === salt);
      requests.push({ credentialId: id, salt, replayed: !!hit });
      if (!hit) return credential;
      const bytes = fromHex(hit.output);
      if (corrupt) bytes[0] ^= 1;
      const inner = credential.getClientExtensionResults.bind(credential);
      Object.defineProperty(credential, "getClientExtensionResults", {
        configurable: true,
        value: () =>
          Object.assign({}, inner(), {
            prf: { results: { first: bytes.buffer } },
          }),
      });
      return credential;
    },
  });
})(${JSON.stringify(records)}, ${options.corrupt === true});`);
}

/** What the app asked for in the CURRENT document. */
export async function readPrfRequests(page: Page): Promise<PrfRequest[]> {
  return page.evaluate(
    () =>
      ((window as unknown as { __prfRequests?: unknown[] }).__prfRequests ??
        []) as unknown as {
        credentialId: string;
        salt: string;
        replayed: boolean;
      }[],
  );
}
