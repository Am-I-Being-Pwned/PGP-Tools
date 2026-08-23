import tailwindcss from "@tailwindcss/vite";
import wasm from "vite-plugin-wasm";
import { defineConfig } from "wxt";

const isDev = process.env.NODE_ENV === "development";

// Production CSP: locked-down. The audit story (see SECURITY.md §7)
// depends on this exact policy.
const PROD_CSP =
  [
    "default-src 'none'",
    "script-src 'self' 'wasm-unsafe-eval'",
    // Widened for the GitHub SSH-recipient import. CSP applies to the
    // MV3 service worker (verified: with plain `connect-src 'self'` the
    // worker's fetch to api.github.com fails), so the worker cannot
    // reach the endpoint without this entry.
    //
    // What the `/users/` path prefix buys: other API paths are blocked
    // -- verified that `/users/<name>/keys` returns 200 while `/gists`
    // is refused by the browser. What it does NOT buy: CSP does not
    // path-match query strings, so `?anything=x` appended to an allowed
    // path still passes. The real defence against a crafted path is
    // lib/github/username.ts, which pins the username charset and
    // asserts the final origin + pathname before fetching.
    //
    // The side panel does not need this and does not get it: its
    // index.html carries a meta CSP that keeps it on `connect-src
    // 'self'`. Only the worker talks to GitHub.
    "connect-src 'self' https://api.github.com/users/",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "worker-src 'self'",
    "frame-src 'none'",
    "child-src 'none'",
    "form-action 'none'",
    "object-src 'none'",
    "media-src 'none'",
    "base-uri 'none'",
    "manifest-src 'none'",
  ].join("; ") + ";";

/**
 * Inject the side panel's tightening meta CSP -- PRODUCTION ONLY.
 *
 * A meta CSP can only ever narrow the policy the manifest sets, which is
 * exactly what we want in prod: the manifest widens `connect-src` so the
 * background worker can reach api.github.com, and this pulls the PANEL
 * back to `connect-src 'self'`, browser-enforced, so the realm holding
 * keys and plaintext cannot name a remote host. MV3 has one CSP for all
 * contexts; this is the only way to scope it per-context.
 *
 * It must NOT ship in dev. `extension_pages` is omitted entirely in dev
 * (see below) so the WXT dev server can serve HMR over ws://localhost
 * and the wasm blob over http://localhost -- a meta tag baked into the
 * HTML has no such mode-awareness and would block both, leaving the
 * panel unable to load its own crypto engine. Hence a build-time
 * injection rather than a literal in index.html.
 */
function panelCspMeta(enabled: boolean) {
  return {
    name: "pgp-tools:panel-csp-meta",
    transformIndexHtml(html: string) {
      if (!enabled) return html;
      return html.replace(
        "<head>",
        `<head>\n    <meta http-equiv="Content-Security-Policy" content="connect-src 'self'" />`,
      );
    },
  };
}

// In dev we omit `content_security_policy.extension_pages` entirely,
// so MV3's default CSP applies (which is already strict and allows
// HMR). Loosening our prod CSP for dev kept hitting MV3's "insecure
// value" rejections; not worth the fight.

/**
 * CHROME (MV3) IS THE ONLY SUPPORTED TARGET.
 *
 * Firefox does not work and is not expected to for the foreseeable
 * future: the blocker is passkey unlock. That path derives its key from
 * the WebAuthn PRF extension (`lib/protection/webauthn-prf.ts`), and
 * without it a passkey-protected vault cannot be opened at all -- this
 * is not a degraded experience, it is a user who cannot reach their
 * keys. Password protection would work; shipping a build where half the
 * protection methods silently fail is worse than shipping none.
 *
 * `dev:firefox`, `build:firefox` and `zip:firefox` still exist in
 * package.json, and stale `*-firefox.zip` artifacts may still be sitting
 * in `.output/`. Neither means the target is supported. Do not publish
 * one without reading the rest of this comment.
 *
 * TWO THINGS TO FIX FIRST if Firefox is ever revived:
 *
 *  1. `build:firefox` and `zip:firefox` run NEITHER audit script --
 *     `pnpm build` chains `audit-invariants` and `audit-network`, those
 *     scripts do not. So the per-context network census, the
 *     "exactly one https origin literal", the host-permissions-absent
 *     check and the panel meta-CSP check are all unenforced on a Firefox
 *     artifact. Today that is harmless only because nothing ships.
 *  2. `validateManifest` in `scripts/audit-network.mjs` reads
 *     `content_security_policy.extension_pages`, which is undefined for
 *     MV2's string-valued CSP -- so it currently emits ~10 spurious CSP
 *     errors against a Firefox build. Anyone wiring the audits in
 *     without fixing that first gets a wall of false positives and will
 *     reasonably conclude the audit is broken rather than the build.
 *
 * CI only ever runs the Chrome build (`.github/workflows/ci.yml`), which
 * is consistent with the above and deliberate.
 */
export default defineConfig({
  modules: ["@wxt-dev/module-react"],
  manifest: () => ({
    name: "PGP Tools - Encrypt, Decrypt & Sign",
    short_name: "PGP Tools",
    description:
      "Encrypt, decrypt, sign, and verify messages with PGP. Drag-and-drop files and manage keys.",
    permissions: ["sidePanel", "contextMenus", "storage", "idle"],
    // Requested at runtime the first time a user saves a signed .crx. Saving
    // goes through chrome.downloads with a "Save As" prompt, the one path that
    // writes a .crx to disk without Chrome trying to install it. (The File
    // System Access picker would avoid this permission but crashes the side
    // panel -- see saveCrxViaPrompt.)
    // `unlimitedStorage` is requested when the user enables the history
    // feature; a denial just keeps history on its conservative byte budget.
    optional_permissions: ["downloads"],
    icons: {
      16: "icon-16.png",
      32: "icon-32.png",
      48: "icon-48.png",
      128: "icon-128.png",
    },
    action: {
      default_title: "PGP Tools",
      default_icon: {
        16: "icon-16.png",
        32: "icon-32.png",
        48: "icon-48.png",
        128: "icon-128.png",
      },
    },
    // Chrome caps an extension at 4 commands WITH suggested keys.
    // _execute_action + the three mode commands below consume all
    // four, so open-verify ships without a default -- users can bind
    // it at chrome://extensions/shortcuts. Command ids are dispatched
    // in background.ts via lib/mode-commands.ts.
    commands: {
      _execute_action: {
        suggested_key: {
          default: "Alt+Shift+G",
          mac: "Alt+Shift+G",
        },
        description: "Open PGP Tools",
      },
      "open-encrypt": {
        suggested_key: {
          default: "Alt+Shift+E",
          mac: "Alt+Shift+E",
        },
        description: "Open PGP Tools in Encrypt mode",
      },
      "open-decrypt": {
        suggested_key: {
          default: "Alt+Shift+D",
          mac: "Alt+Shift+D",
        },
        description: "Open PGP Tools in Decrypt mode",
      },
      "open-sign": {
        suggested_key: {
          default: "Alt+Shift+S",
          mac: "Alt+Shift+S",
        },
        description: "Open PGP Tools in Sign mode",
      },
      "open-verify": {
        description: "Open PGP Tools in Verify mode",
      },
    },
    side_panel: {
      default_path: "sidepanel/index.html",
    },
    ...(isDev
      ? {}
      : {
          content_security_policy: {
            extension_pages: PROD_CSP,
          },
        }),
  }),
  vite: (env) => ({
    plugins: [tailwindcss(), wasm(), panelCspMeta(env.command === "build")],
    server: { port: 3004 },
    build: {
      // We ship to Chrome MV3 only; <link rel="modulepreload"> has
      // been supported since Chrome 66, so the polyfill (which calls
      // fetch on every preload tag) is dead weight. Dropping it
      // removes the only non-essential `fetch` reference from the
      // shipped bundles.
      modulePreload: { polyfill: false },
    },
  }),
  dev: {
    server: {
      port: 3003,
    },
  },
  runner: {
    disabled: true,
  },
});
