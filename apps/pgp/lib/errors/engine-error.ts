/** Error classes the engine tags. Must match `ErrorCode` in
 *  `gpg-wasm/src/error_code.rs`. */
export const ENGINE_ERROR_CODES = [
  "wrong-passphrase",
  "not-encrypted",
  "too-large",
  "symmetric-wrong-password",
  "ocb-unsupported",
  "no-decryption-key",
  "not-crx",
  "crx-unsigned",
  "text-outside-signature",
  "key-expired",
  "key-revoked",
  "not-pgp-data",
] as const;

export type EngineErrorCode = (typeof ENGINE_ERROR_CODES)[number];

/**
 * A coded engine error. `message` is the engine's own text (shown only as
 * the detail line); `code` is what `presentError` classifies on.
 *
 * Deliberately NOT an `Error`: it replaces a thrown string, and sites that
 * show `e instanceof Error ? e.message : <generic>` must keep showing the
 * generic copy for engine failures. `toString()` keeps `String(e)` and
 * template use identical to the bare string.
 */
export class EngineError {
  readonly name = "EngineError";

  constructor(
    readonly code: EngineErrorCode,
    readonly message: string,
  ) {}

  toString(): string {
    return this.message;
  }
}

// Wire form: `\x1f<code>\x1f<message>`; only a leading prefix counts.
const SEP = "\u001f";
const CODE_NAME = /^[a-z-]+$/;

function isEngineErrorCode(s: string): s is EngineErrorCode {
  return (ENGINE_ERROR_CODES as readonly string[]).includes(s);
}

/** Decode an engine error string: an `EngineError` if it carries a known
 *  code, else the string (an unknown code stripped, never classified). */
export function decodeEngineError(raw: string): EngineError | string {
  if (!raw.startsWith(SEP)) return raw;
  const end = raw.indexOf(SEP, SEP.length);
  const name = raw.slice(SEP.length, end);
  if (end < 0 || !CODE_NAME.test(name)) return raw;
  const message = raw.slice(end + SEP.length);
  return isEngineErrorCode(name) ? new EngineError(name, message) : message;
}

/** `mod` with every function's thrown string decoded -- the ONE place
 *  engine error codes are read off the wire. Untagged strings are
 *  rethrown as-is (value-matched sentinels such as
 *  `outputCapReachedMessage()` depend on that). */
export function withEngineErrors<M extends object>(mod: M): M {
  const wrapped: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(mod)) {
    if (typeof value !== "function") {
      wrapped[name] = value;
      continue;
    }
    const fn = value as (...args: unknown[]) => unknown;
    wrapped[name] = (...args: unknown[]) => {
      try {
        return fn(...args);
      } catch (e) {
        throw typeof e === "string" ? decodeEngineError(e) : e;
      }
    };
  }
  return wrapped as M;
}
