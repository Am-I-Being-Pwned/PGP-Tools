/**
 * Runtime network hooks — MUST be the first import in every entrypoint.
 *
 * Hooks are frozen + non-configurable. CSP covers iframes (frame-src
 * 'none') and inline scripts (no 'unsafe-inline'), so no DOM hooks needed.
 */

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
    return Promise.reject(new TypeError("NetworkLockdown: HTTP not allowed, use HTTPS"));
  }

  const method = (
    init?.method ??
    (input instanceof Request ? input.method : "GET")
  ).toUpperCase();

  if (BLOCKED_METHODS.has(method)) {
    console.error(`[network-lockdown] Blocked ${method} to ${url}`);
    return Promise.reject(new TypeError(`NetworkLockdown: ${method} not allowed`));
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

export {};
