/**
 * @vitest-environment jsdom
 *
 * The WebAuthn PRF ceremony.
 *
 * Three things here are worth pinning, and none of them is "does it call
 * navigator.credentials":
 *
 *  1. THE PRF EXTENSION IS ACTUALLY REQUESTED. `extensions.prf` on
 *     create, and `extensions.prf.eval.first` with the stored salt on
 *     get. Drop either and the ceremony still succeeds -- it just returns
 *     no PRF output, and every key protected by that passkey becomes
 *     permanently unopenable. Nothing else in the system catches it.
 *
 *  2. A MISSING PRF RESULT THROWS RATHER THAN RETURNING EMPTY BYTES. An
 *     authenticator that ignores the extension returns a credential with
 *     no `results.first`. Deriving a key from undefined-shaped input is
 *     the one outcome worse than failing.
 *
 *  3. CANCEL IS DISTINGUISHED FROM FAILURE. `isWebAuthnCancel` decides
 *     whether the user sees an error toast; the user dismissing Touch ID
 *     is not an error.
 *
 * `navigator.credentials` and `PublicKeyCredential` don't exist in jsdom,
 * so both are stubbed. The `instanceof PublicKeyCredential` check in the
 * module means the stub has to be a real class, not a plain object.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { toBase64url } from "../encoding.ts";
import {
  authenticateAndGetPrf,
  cancelPasskeyPrompt,
  checkPrfSupport,
  generatePrfSalt,
  generateStoredSecret,
  isPasskeyPromptOpen,
  isWebAuthnCancel,
  PasskeyPromptBlockedError,
  PrfNotSupportedError,
  registerPasskey,
  subscribePasskeyPrompt,
} from "./webauthn-prf";

// ── stubs ────────────────────────────────────────────────────────────

/** Stands in for the real interface object; the module gates on
 *  `instanceof`, so a plain object would be rejected as a failure. */
class FakeCredential {
  rawId: ArrayBuffer;
  private ext: Record<string, unknown>;

  constructor(rawId: ArrayBuffer, ext: Record<string, unknown>) {
    this.rawId = rawId;
    this.ext = ext;
  }

  getClientExtensionResults() {
    return this.ext;
  }
}

let create: ReturnType<
  typeof vi.fn<(o: CredentialCreationOptions) => Promise<unknown>>
>;
let get: ReturnType<
  typeof vi.fn<(o: CredentialRequestOptions) => Promise<unknown>>
>;

/** Byte length of a `BufferSource`, which is either an ArrayBuffer or a
 *  view over one -- both carry `byteLength`. */
function byteLength(buf: BufferSource): number {
  return buf.byteLength;
}

/** The `publicKey` block handed to `navigator.credentials.create` on call `i`. */
function createArgs(i = 0): PublicKeyCredentialCreationOptions {
  const opts = create.mock.calls[i][0];
  if (!opts.publicKey) throw new Error("create() called without publicKey");
  return opts.publicKey;
}

/** The `publicKey` block handed to `navigator.credentials.get` on call `i`. */
function getArgs(i = 0): PublicKeyCredentialRequestOptions {
  const opts = get.mock.calls[i][0];
  if (!opts.publicKey) throw new Error("get() called without publicKey");
  return opts.publicKey;
}

function stubCredentials(
  opts: {
    create?: unknown;
    get?: unknown;
  } = {},
) {
  create = vi.fn((_o: CredentialCreationOptions) =>
    opts.create instanceof Error
      ? Promise.reject(opts.create)
      : Promise.resolve(opts.create ?? null),
  );
  get = vi.fn((_o: CredentialRequestOptions) =>
    opts.get instanceof Error
      ? Promise.reject(opts.get)
      : Promise.resolve(opts.get ?? null),
  );
  Object.defineProperty(navigator, "credentials", {
    value: { create, get },
    configurable: true,
  });
}

function stubUserAgent(ua: string) {
  Object.defineProperty(navigator, "userAgent", {
    value: ua,
    configurable: true,
  });
}

const RAW_ID = new Uint8Array([1, 2, 3, 4]).buffer;

beforeEach(() => {
  vi.stubGlobal("PublicKeyCredential", FakeCredential);
  stubCredentials();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

// ── random material ──────────────────────────────────────────────────

describe("authenticateAndGetPrf with a second salt", () => {
  // "Unlock keys with the vault" re-seals a key under the master salt
  // off the key's OWN prompt, which is only possible because the PRF
  // extension evaluates two salts per ceremony. Drop the `second`
  // request and the re-seal silently never happens; return a `second`
  // that was not asked for and a caller might zero the wrong thing.
  const FIRST = new Uint8Array(32).fill(0xa1).buffer;
  const SECOND = new Uint8Array(32).fill(0xb2).buffer;

  it("requests both salts and returns both outputs", async () => {
    stubCredentials({
      get: new FakeCredential(RAW_ID, {
        prf: { results: { first: FIRST, second: SECOND } },
      }),
    });

    const { prfOutput, secondOutput } = await authenticateAndGetPrf(
      toBase64url(RAW_ID),
      new Uint8Array(32).fill(1),
      undefined,
      new Uint8Array(32).fill(2),
    );

    const evalArg = getArgs().extensions?.prf?.eval;
    expect(evalArg && byteLength(evalArg.first)).toBe(32);
    expect(evalArg?.second && byteLength(evalArg.second)).toBe(32);
    expect([...prfOutput]).toEqual(new Array(32).fill(0xa1));
    expect(secondOutput && [...secondOutput]).toEqual(new Array(32).fill(0xb2));
  });

  it("requests only `first` and returns no `secondOutput` when no second salt is given", async () => {
    stubCredentials({
      get: new FakeCredential(RAW_ID, {
        prf: { results: { first: FIRST, second: SECOND } },
      }),
    });

    const result = await authenticateAndGetPrf(
      toBase64url(RAW_ID),
      new Uint8Array(32).fill(1),
    );

    expect(getArgs().extensions?.prf?.eval?.second).toBeUndefined();
    expect(result).not.toHaveProperty("secondOutput");
  });

  it("still unlocks when the authenticator ignores the second salt", async () => {
    // A re-seal that cannot happen must not cost the user the unlock.
    stubCredentials({
      get: new FakeCredential(RAW_ID, { prf: { results: { first: FIRST } } }),
    });

    const result = await authenticateAndGetPrf(
      toBase64url(RAW_ID),
      new Uint8Array(32).fill(1),
      undefined,
      new Uint8Array(32).fill(2),
    );

    expect([...result.prfOutput]).toEqual(new Array(32).fill(0xa1));
    expect(result.secondOutput).toBeUndefined();
  });
});

describe("random material", () => {
  it.each([
    ["generatePrfSalt", generatePrfSalt],
    ["generateStoredSecret", generateStoredSecret],
  ])("%s returns 32 fresh bytes", (_name, fn) => {
    const a = new Uint8Array(fn());
    const b = new Uint8Array(fn());
    expect(a).toHaveLength(32);
    // Not a randomness test -- a stubbed-out or constant generator would
    // make every vault derive the same key, so identical draws are the
    // failure worth catching.
    expect(a).not.toEqual(b);
  });
});

describe("checkPrfSupport", () => {
  it.each([
    ["Mozilla/5.0 Chrome/120", true],
    ["Mozilla/5.0 Version/17 Safari/605", true],
    ["Mozilla/5.0 Firefox/121", true],
    ["Mozilla/5.0 SomeOtherBrowser/1", false],
  ])("reports %s as %s", (ua, expected) => {
    stubUserAgent(ua);
    expect(checkPrfSupport()).toBe(expected);
  });
});

// ── registration ─────────────────────────────────────────────────────

describe("registerPasskey", () => {
  function credential(
    ext: Record<string, unknown> = { prf: { enabled: true } },
  ) {
    return new FakeCredential(RAW_ID, ext);
  }

  it("requests the prf extension", async () => {
    // Without this, registration succeeds and PRF silently never works.
    stubCredentials({ create: credential() });
    await registerPasskey();
    expect(createArgs().extensions).toEqual({ prf: {} });
  });

  it("asks for a discoverable credential with a 32-byte challenge", async () => {
    stubCredentials({ create: credential() });
    await registerPasskey();

    const publicKey = createArgs();
    expect(publicKey.authenticatorSelection).toMatchObject({
      residentKey: "required",
      requireResidentKey: true,
    });
    expect(byteLength(publicKey.challenge)).toBe(32);
  });

  it("offers both ES256 and RS256", async () => {
    // A security key that does only RS256 must still be usable.
    stubCredentials({ create: credential() });
    await registerPasskey();
    expect(createArgs().pubKeyCredParams.map((p) => p.alg)).toEqual([-7, -257]);
  });

  it("returns the credential id base64url-encoded", async () => {
    stubCredentials({ create: credential() });
    const result = await registerPasskey();
    expect(result.credentialId).toBe(toBase64url(RAW_ID));
  });

  it("reports prfEnabled from the extension result", async () => {
    stubCredentials({ create: credential({ prf: { enabled: true } }) });
    await expect(registerPasskey()).resolves.toMatchObject({
      prfEnabled: true,
    });
  });

  it.each([
    ["enabled is false", { prf: { enabled: false } }],
    ["prf is absent", {}],
    ["enabled is merely truthy, not true", { prf: { enabled: "yes" } }],
  ])("reports prfEnabled false when %s", async (_label, ext) => {
    stubCredentials({ create: credential(ext) });
    await expect(registerPasskey()).resolves.toMatchObject({
      prfEnabled: false,
    });
  });

  it("uses the supplied names, falling back sensibly", async () => {
    stubCredentials({ create: credential() });

    await registerPasskey("alice@example.com", "Alice");
    expect(createArgs().user).toMatchObject({
      name: "alice@example.com",
      displayName: "Alice",
    });

    // displayName omitted falls back to the user name, then to a default.
    await registerPasskey("alice@example.com");
    expect(createArgs(1).user.displayName).toBe("alice@example.com");

    await registerPasskey();
    expect(createArgs(2).user).toMatchObject({
      name: "PGP Key Protection",
      displayName: "PGP Key Protection",
    });
  });

  it("forwards an abort signal", async () => {
    // The ceremony gate hands the browser its own signal; aborting the
    // caller's must abort that one.
    const controller = new AbortController();
    stubCredentials();
    create.mockImplementation(
      (o) =>
        new Promise((_resolve, reject) =>
          o.signal?.addEventListener("abort", () =>
            reject(new DOMException("aborted", "AbortError")),
          ),
        ),
    );
    const pending = registerPasskey(undefined, undefined, controller.signal);
    await vi.waitFor(() => expect(create).toHaveBeenCalled());
    const forwarded = create.mock.calls[0][0].signal;
    expect(forwarded?.aborted).toBe(false);
    controller.abort();
    expect(forwarded?.aborted).toBe(true);
    await expect(pending).rejects.toBeDefined();
  });

  it("requires user verification, matching authentication", async () => {
    // "preferred" lets a PIN-less security key register, then forces
    // PIN setup at its first unlock.
    stubCredentials({ create: credential() });
    await registerPasskey();
    expect(createArgs().authenticatorSelection?.userVerification).toBe(
      "required",
    );
  });

  it("asks for PRF output at registration when given a salt", async () => {
    const salt = new Uint8Array(32).fill(3);
    const first = new Uint8Array([5, 6, 7]).buffer;
    stubCredentials({
      create: credential({ prf: { enabled: true, results: { first } } }),
    });
    const reg = await registerPasskey(undefined, undefined, undefined, salt);
    expect(createArgs().extensions).toEqual({
      prf: { eval: { first: salt } },
    });
    expect(reg.prfOutput).toEqual(new Uint8Array([5, 6, 7]));
  });

  it("returns no PRF output when the authenticator only evaluates it later", async () => {
    stubCredentials({ create: credential({ prf: { enabled: false } }) });
    const reg = await registerPasskey(
      undefined,
      undefined,
      undefined,
      new Uint8Array(32),
    );
    expect(reg.prfOutput).toBeUndefined();
  });

  it("throws when the ceremony returns nothing", async () => {
    stubCredentials({ create: null });
    await expect(registerPasskey()).rejects.toThrow(/registration failed/i);
  });

  it("throws when the ceremony returns something that isn't a credential", async () => {
    stubCredentials({ create: { rawId: RAW_ID } });
    await expect(registerPasskey()).rejects.toThrow(/registration failed/i);
  });
});

// ── authentication ───────────────────────────────────────────────────

describe("authenticateAndGetPrf", () => {
  const SALT = new Uint8Array(32).fill(7);
  const PRF = new Uint8Array([9, 8, 7, 6]).buffer;

  function credential(
    ext: Record<string, unknown> = { prf: { results: { first: PRF } } },
  ) {
    return new FakeCredential(RAW_ID, ext);
  }

  it("evaluates the prf extension with the stored salt", async () => {
    // The (credentialId, salt) pair is what makes the derived key stable
    // across unlocks. A wrong or missing salt derives a different key and
    // the vault will not open.
    stubCredentials({ get: credential() });
    await authenticateAndGetPrf(toBase64url(RAW_ID), SALT);

    expect(getArgs().extensions).toEqual({
      prf: { eval: { first: SALT } },
    });
  });

  it("requires user verification and allows the stored credential", async () => {
    stubCredentials({ get: credential() });
    await authenticateAndGetPrf(toBase64url(RAW_ID), SALT);

    const publicKey = getArgs();
    expect(publicKey.userVerification).toBe("required");

    const allowed = publicKey.allowCredentials ?? [];
    expect(allowed).toHaveLength(1);
    expect(new Uint8Array(allowed[0].id as ArrayBuffer)).toEqual(
      new Uint8Array(RAW_ID),
    );
  });

  it("returns the raw PRF bytes", async () => {
    // Raw, not derived: HKDF happens in WASM so the key never enters the
    // JS heap.
    stubCredentials({ get: credential() });
    const { prfOutput } = await authenticateAndGetPrf(
      toBase64url(RAW_ID),
      SALT,
    );
    expect(prfOutput).toEqual(new Uint8Array([9, 8, 7, 6]));
  });

  it("forwards an abort signal", async () => {
    const controller = new AbortController();
    stubCredentials();
    get.mockImplementation(
      (o) =>
        new Promise((_resolve, reject) =>
          o.signal?.addEventListener("abort", () =>
            reject(new DOMException("aborted", "AbortError")),
          ),
        ),
    );
    const pending = authenticateAndGetPrf(
      toBase64url(RAW_ID),
      SALT,
      controller.signal,
    );
    await vi.waitFor(() => expect(get).toHaveBeenCalled());
    const forwarded = get.mock.calls[0][0].signal;
    expect(forwarded?.aborted).toBe(false);
    controller.abort();
    expect(forwarded?.aborted).toBe(true);
    await expect(pending).rejects.toBeDefined();
  });

  it.each([
    ["prf is absent entirely", {}],
    ["results is absent", { prf: {} }],
    ["first is absent", { prf: { results: {} } }],
  ])("throws PrfNotSupportedError when %s", async (_label, ext) => {
    // Never fall through to deriving a key from an absent PRF result.
    stubCredentials({ get: credential(ext) });
    await expect(
      authenticateAndGetPrf(toBase64url(RAW_ID), SALT),
    ).rejects.toBeInstanceOf(PrfNotSupportedError);
  });

  it("throws when the ceremony returns nothing", async () => {
    stubCredentials({ get: null });
    await expect(
      authenticateAndGetPrf(toBase64url(RAW_ID), SALT),
    ).rejects.toThrow(/authentication failed/i);
  });
});

// ── error classification ─────────────────────────────────────────────

describe("isWebAuthnCancel", () => {
  function named(name: string) {
    const e = new Error("x");
    e.name = name;
    return e;
  }

  it.each([["NotAllowedError"], ["AbortError"], ["InvalidStateError"]])(
    "treats %s as a cancel",
    (name) => {
      // These are the user dismissing the prompt, the flow aborting, and
      // the "request already pending" race -- none deserves a toast.
      expect(isWebAuthnCancel(named(name))).toBe(true);
    },
  );

  it.each([["NotSupportedError"], ["SecurityError"], ["TypeError"]])(
    "treats %s as a real failure",
    (name) => {
      expect(isWebAuthnCancel(named(name))).toBe(false);
    },
  );

  it.each([
    ["a string", "NotAllowedError"],
    ["null", null],
    ["undefined", undefined],
    ["a plain object wearing the name", { name: "NotAllowedError" }],
  ])("returns false for %s", (_label, value) => {
    expect(isWebAuthnCancel(value)).toBe(false);
  });
});

describe("PrfNotSupportedError", () => {
  it("names the macOS requirement on a Mac", () => {
    stubUserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605");
    expect(new PrfNotSupportedError().message).toMatch(/macOS requires 15\+/);
  });

  it("points Windows users at a security key", () => {
    stubUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/121");
    expect(new PrfNotSupportedError().message).toMatch(/YubiKey/);
  });

  it("adds the Chrome profile hint on desktop Chrome only", () => {
    stubUserAgent("Mozilla/5.0 (Windows NT 10.0) Chrome/120");
    expect(new PrfNotSupportedError().message).toMatch(/Chrome profile/);

    stubUserAgent("Mozilla/5.0 (Linux; Android 14) Chrome/120 Mobile");
    expect(new PrfNotSupportedError().message).not.toMatch(/Chrome profile/);
  });

  it("still explains itself on an unrecognised platform", () => {
    stubUserAgent("Mozilla/5.0 (X11; Linux x86_64) Konqueror/5");
    const message = new PrfNotSupportedError().message;
    expect(message).toMatch(/PRF not supported/);
    expect(message).toBe(message.trim());
  });

  it("carries its own name so callers can branch on it", () => {
    stubUserAgent("Mozilla/5.0 Chrome/120");
    expect(new PrfNotSupportedError().name).toBe("PrfNotSupportedError");
  });
});

// ── ceremony gate ────────────────────────────────────────────────────

describe("the passkey ceremony gate", () => {
  // Browsers allow one pending WebAuthn request, and Windows Hello /
  // Chrome's Linux UI release it asynchronously after an abort. These
  // pin the behaviour that keeps a re-click or a second flow from
  // landing on "A request is already pending" and silently doing nothing.
  const SALT = new Uint8Array(32).fill(7);
  const PRF = new Uint8Array([1, 1, 1]).buffer;
  const ok = () =>
    new FakeCredential(RAW_ID, { prf: { results: { first: PRF } } });

  function named(name: string, message = "x") {
    const e = new Error(message);
    e.name = name;
    return e;
  }

  /** A `get` that stays pending until its signal aborts. */
  function hangingGet() {
    return (o: CredentialRequestOptions) =>
      new Promise<unknown>((_resolve, reject) => {
        o.signal?.addEventListener("abort", () => reject(named("AbortError")));
      });
  }

  /** Make every ceremony look like it took `ms` of wall time. */
  function elapse(ms: number) {
    let now = 0;
    vi.spyOn(performance, "now").mockImplementation(() => {
      const t = now;
      now += ms;
      return t;
    });
  }

  it("reports a prompt as open until it settles", async () => {
    let finish!: (v: unknown) => void;
    stubCredentials();
    get.mockImplementation(() => new Promise((r) => (finish = r)));

    expect(isPasskeyPromptOpen()).toBe(false);
    const listener = vi.fn();
    const unsubscribe = subscribePasskeyPrompt(listener);
    const p = authenticateAndGetPrf(toBase64url(RAW_ID), SALT);
    expect(isPasskeyPromptOpen()).toBe(true);
    await vi.waitFor(() => expect(get).toHaveBeenCalled());
    finish(ok());
    await p;
    expect(isPasskeyPromptOpen()).toBe(false);
    expect(listener).toHaveBeenCalled();
    unsubscribe();
  });

  it("cancelPasskeyPrompt aborts the open ceremony as a cancel", async () => {
    stubCredentials();
    get.mockImplementation(hangingGet());
    const p = authenticateAndGetPrf(toBase64url(RAW_ID), SALT);
    await vi.waitFor(() => expect(get).toHaveBeenCalled());
    cancelPasskeyPrompt();
    const err = await p.catch((e: unknown) => e);
    expect(isWebAuthnCancel(err)).toBe(true);
    expect(isPasskeyPromptOpen()).toBe(false);
  });

  it("a new ceremony waits for the one it supersedes to settle", async () => {
    stubCredentials();
    get.mockImplementationOnce(hangingGet()).mockResolvedValueOnce(ok());

    const first = authenticateAndGetPrf(toBase64url(RAW_ID), SALT);
    await vi.waitFor(() => expect(get).toHaveBeenCalledTimes(1));
    const second = authenticateAndGetPrf(toBase64url(RAW_ID), SALT);

    const firstErr = await first.catch((e: unknown) => e);
    expect(isWebAuthnCancel(firstErr)).toBe(true);
    await expect(second).resolves.toMatchObject({
      prfOutput: new Uint8Array([1, 1, 1]),
    });
    // The second request was issued only after the first had settled.
    expect(get).toHaveBeenCalledTimes(2);
    expect(isPasskeyPromptOpen()).toBe(false);
  });

  it.each([
    ["InvalidStateError", "A request is already pending."],
    ["OperationError", "A request is already pending."],
  ])(
    "retries a %s 'already pending' until the browser lets go",
    async (name, msg) => {
      vi.useFakeTimers();
      try {
        stubCredentials();
        get.mockRejectedValueOnce(named(name, msg)).mockResolvedValueOnce(ok());
        const p = authenticateAndGetPrf(toBase64url(RAW_ID), SALT);
        await vi.advanceTimersByTimeAsync(1_000);
        await expect(p).resolves.toMatchObject({
          prfOutput: new Uint8Array([1, 1, 1]),
        });
        expect(get).toHaveBeenCalledTimes(2);
      } finally {
        vi.useRealTimers();
      }
    },
  );

  it("gives up on a request that stays pending with a visible error", async () => {
    vi.useFakeTimers();
    try {
      stubCredentials({ get: named("InvalidStateError", "pending") });
      const p = authenticateAndGetPrf(toBase64url(RAW_ID), SALT).catch(
        (e: unknown) => e,
      );
      await vi.advanceTimersByTimeAsync(5_000);
      const err = await p;
      expect(err).toBeInstanceOf(PasskeyPromptBlockedError);
      // Not a cancel: the user did nothing, so it must be shown.
      expect(isWebAuthnCancel(err)).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not retry an OperationError that isn't about a pending request", async () => {
    stubCredentials({ get: named("OperationError", "authenticator error") });
    await expect(
      authenticateAndGetPrf(toBase64url(RAW_ID), SALT),
    ).rejects.toMatchObject({ name: "OperationError" });
    expect(get).toHaveBeenCalledTimes(1);
  });

  it("an instant NotAllowedError means the prompt never showed", async () => {
    // e.g. the side panel did not have focus. Swallowing this as a
    // cancel is what made the unlock button look dead.
    elapse(10);
    stubCredentials({ get: named("NotAllowedError") });
    await expect(
      authenticateAndGetPrf(toBase64url(RAW_ID), SALT),
    ).rejects.toBeInstanceOf(PasskeyPromptBlockedError);
  });

  it("a NotAllowedError after the prompt was up is the user cancelling", async () => {
    elapse(3_000);
    stubCredentials({ get: named("NotAllowedError") });
    const err = await authenticateAndGetPrf(toBase64url(RAW_ID), SALT).catch(
      (e: unknown) => e,
    );
    expect(err).toMatchObject({ name: "NotAllowedError" });
    expect(isWebAuthnCancel(err)).toBe(true);
  });

  it("registration goes through the same gate", async () => {
    stubCredentials();
    get.mockImplementation(hangingGet());
    create.mockResolvedValue(new FakeCredential(RAW_ID, {}));
    const auth = authenticateAndGetPrf(toBase64url(RAW_ID), SALT);
    await vi.waitFor(() => expect(get).toHaveBeenCalled());
    const reg = registerPasskey();
    expect(isWebAuthnCancel(await auth.catch((e: unknown) => e))).toBe(true);
    await expect(reg).resolves.toMatchObject({
      credentialId: toBase64url(RAW_ID),
    });
  });
});
