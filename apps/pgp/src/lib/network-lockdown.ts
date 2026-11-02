/**
 * Runtime lockdown — MUST be the first import in every entrypoint; both
 * jobs depend on running before any dependency:
 *   1. Outbound network hooks (§7) — fetch/XHR/WS/EventSource/RTC/beacon.
 *   2. Boundary primitive freeze (§8.10) — see the block at the bottom.
 *
 * The path is an exemption in scripts/audit-invariants.mjs. Hooks are
 * frozen + non-configurable; CSP covers iframes and inline scripts.
 * No-ops in dev (HMR needs WebSocket); production builds always lock down.
 */

if (import.meta.env.DEV) {
  // No-op in dev; see SECURITY.md §7.
} else {
  const isExtensionUrl = (url: string) => url.startsWith("chrome-extension://");
  const BLOCKED_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

  const _fetch = globalThis.fetch;

  function lockedFetch(
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> {
    const url =
      input instanceof Request
        ? input.url
        : input instanceof URL
          ? input.href
          : String(input);

    if (isExtensionUrl(url)) return _fetch(input, init);

    if (url.startsWith("http://")) {
      console.error(`[network-lockdown] Blocked HTTP request to ${url}`);
      return Promise.reject(
        new TypeError("NetworkLockdown: HTTP not allowed, use HTTPS"),
      );
    }

    const method = (
      init?.method ?? (input instanceof Request ? input.method : "GET")
    ).toUpperCase();

    if (BLOCKED_METHODS.has(method)) {
      console.error(`[network-lockdown] Blocked ${method} to ${url}`);
      return Promise.reject(
        new TypeError(`NetworkLockdown: ${method} not allowed`),
      );
    }

    return _fetch(input, {
      ...init,
      credentials: "omit",
      headers: stripSensitiveHeaders(
        init?.headers ?? (input instanceof Request ? input.headers : undefined),
      ),
    });
  }

  function stripSensitiveHeaders(headers: HeadersInit | undefined): Headers {
    const out = new Headers(headers);
    out.delete("Authorization");
    out.delete("Cookie");
    out.delete("X-Api-Key");
    return out;
  }

  Object.defineProperty(globalThis, "fetch", {
    value: Object.freeze(lockedFetch),
    writable: false,
    configurable: false,
  });

  function blockApi(obj: object, name: string, replacement: () => void) {
    if (typeof (obj as Record<string, unknown>)[name] === "undefined") return;
    Object.defineProperty(obj, name, {
      value: Object.freeze(replacement),
      writable: false,
      configurable: false,
    });
  }

  blockApi(globalThis, "XMLHttpRequest", function XMLHttpRequest() {
    throw new TypeError("NetworkLockdown: XMLHttpRequest not allowed");
  });
  blockApi(globalThis, "WebSocket", function WebSocket() {
    throw new TypeError("NetworkLockdown: WebSocket not allowed");
  });
  blockApi(globalThis, "EventSource", function EventSource() {
    throw new TypeError("NetworkLockdown: EventSource not allowed");
  });
  blockApi(globalThis, "RTCPeerConnection", function RTCPeerConnection() {
    throw new TypeError("NetworkLockdown: RTCPeerConnection not allowed");
  });

  if (typeof globalThis.navigator.sendBeacon === "function") {
    Object.defineProperty(navigator, "sendBeacon", {
      value: Object.freeze(function sendBeacon() {
        console.error("[network-lockdown] Blocked sendBeacon");
        return false;
      }),
      writable: false,
      configurable: false,
    });
  }

  // ── Boundary primitive freeze — SECURITY.md §8.10 ──────────────────
  // The wasm-bindgen glue looks these up per call, so patching one taps
  // every secret crossing the boundary (password encode, every returned
  // string, the ONLY entropy source, clipboard writes). Meaningful only
  // because this is the first import; it does not stop earlier-loaded code
  // or a hostile realm calling wasm directly. Raises cost, not a fix.
  // Threats: T-PRIMITIVE-HOOK, T-ENTROPY-POISON.
  function freezeMethod(obj: object | undefined, name: string) {
    if (!obj) return;
    const desc = Object.getOwnPropertyDescriptor(obj, name);
    if (!desc || typeof desc.value !== "function" || !desc.configurable) return;
    Object.defineProperty(obj, name, {
      value: desc.value,
      writable: false,
      configurable: false,
      enumerable: desc.enumerable,
    });
  }

  freezeMethod(TextEncoder.prototype, "encode");
  freezeMethod(TextEncoder.prototype, "encodeInto");
  freezeMethod(TextDecoder.prototype, "decode");
  freezeMethod(globalThis.Crypto.prototype, "getRandomValues");
  // Clipboard does not exist in the service worker; an unguarded access
  // throws at module scope and silently kills the whole worker (see
  // SECURITY.md). The cast states that the realm may be a worker, which
  // the DOM lib types deny.
  const realm = globalThis as {
    Clipboard?: typeof Clipboard;
    navigator?: { clipboard?: Navigator["clipboard"] };
  };

  if (realm.Clipboard !== undefined) {
    freezeMethod(realm.Clipboard.prototype, "writeText");
  }

  // An own property on an extensible instance shadows the frozen
  // prototype method, so pin the instance slot too.
  function pinOwnMethod(obj: object, name: string) {
    const current = (obj as Record<string, unknown>)[name];
    if (typeof current !== "function") return;
    const bound = (current as (...a: unknown[]) => unknown).bind(obj);
    Object.defineProperty(obj, name, {
      value: Object.freeze(bound),
      writable: false,
      configurable: false,
      enumerable: false,
    });
  }

  // No `navigator.clipboard` in a worker realm.
  if (realm.navigator?.clipboard !== undefined) {
    pinOwnMethod(realm.navigator.clipboard, "writeText");
  }

  // getrandom's wasm backend looks up `getRandomValues` on the cached
  // Crypto instance per call, so the instance slot is T-ENTROPY-POISON's
  // actual route.
  pinOwnMethod(globalThis.crypto, "getRandomValues");
} // end !import.meta.env.DEV

export {};
