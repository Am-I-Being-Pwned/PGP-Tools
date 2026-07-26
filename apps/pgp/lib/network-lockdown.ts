/**
 * Runtime lockdown — MUST be the first import in every entrypoint.
 *
 * Two jobs, and the "first import" guarantee is what makes both work:
 *   1. Outbound network hooks (§7) — fetch/XHR/WS/EventSource/RTC/beacon.
 *   2. Boundary primitive freeze (§8.10) — pins the encode/decode/RNG/
 *      clipboard methods the wasm boundary depends on, so a dependency
 *      loaded after us cannot patch them. See the block at the bottom.
 *
 * (The filename still says "network" for historical reasons; scope is now
 * broader. Renaming means touching every entrypoint import plus the
 * exemption path in scripts/audit-invariants.mjs.)
 *
 * Hooks are frozen + non-configurable. CSP covers iframes (frame-src
 * 'none') and inline scripts (no 'unsafe-inline'), so no DOM hooks needed.
 *
 * In dev (Vite/WXT HMR), this whole module no-ops -- the dev server
 * uses WebSocket and various transports the production lockdown
 * blocks. Production builds (`wxt build`) always run the lockdown.
 */

if (import.meta.env.DEV) {
  // No-op in dev so HMR can use WebSocket etc. See SECURITY.md §7 --
  // production CSP + this lockdown together pin outbound network.
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
  //
  // The wasm-bindgen glue looks each of these up per call, so a
  // dependency that patches one taps every secret crossing the boundary:
  //
  //   TextEncoder.encode      the unlock password, as React converts it
  //   TextDecoder.decode      every string WASM returns -- so even a
  //                           perfectly gated export path leaks while the
  //                           user does a LEGITIMATE export
  //   getRandomValues         the module's ONLY entropy source; a constant
  //                           return makes every key generated afterwards
  //                           predictable, silently and with no artefact
  //   Clipboard.writeText     read at write time, which the 30s/60s
  //                           auto-clear cannot reach
  //
  // Freezing them non-writable/non-configurable is meaningful ONLY because
  // this module is the first import in every entrypoint, so code loaded
  // later cannot patch them. It does NOT stop a dependency that runs
  // earlier in the module graph, and it does nothing about a hostile
  // realm calling the wasm exports directly (§8.10). This raises an
  // attacker's cost; it does not close the hole.
  //
  // Threats: T-PRIMITIVE-HOOK, T-ENTROPY-POISON.
  function freezeMethod(obj: object | undefined, name: string) {
    if (!obj) return;
    const desc = Object.getOwnPropertyDescriptor(obj, name);
    // Skip anything absent, non-method, or already locked down.
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
  freezeMethod(globalThis.Clipboard.prototype, "writeText");

  // `navigator.clipboard` is an extensible OBJECT, so freezing
  // Clipboard.prototype.writeText alone is not enough -- an own property on
  // the instance shadows the prototype method, which is exactly how a
  // realistic tap is written. Pin the own slot as well.
  const clip = globalThis.navigator.clipboard;
  if (typeof clip.writeText === "function") {
    const boundWrite = clip.writeText.bind(clip);
    Object.defineProperty(clip, "writeText", {
      value: Object.freeze(boundWrite),
      writable: false,
      configurable: false,
      enumerable: false,
    });
  }
} // end !import.meta.env.DEV

export {};
