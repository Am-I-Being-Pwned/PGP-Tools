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
    "connect-src 'self'",
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

// In dev we omit `content_security_policy.extension_pages` entirely,
// so MV3's default CSP applies (which is already strict and allows
// HMR). Loosening our prod CSP for dev kept hitting MV3's "insecure
// value" rejections; not worth the fight.

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
  vite: () => ({
    plugins: [tailwindcss(), wasm()],
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
