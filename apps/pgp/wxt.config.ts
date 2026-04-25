import tailwindcss from "@tailwindcss/vite";
import wasm from "vite-plugin-wasm";
import { defineConfig } from "wxt";

const isDev = process.env.NODE_ENV === "development";

// Production CSP: locked-down. The audit story (see SECURITY.md §7)
// depends on this exact policy.
const PROD_CSP = [
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
    commands: {
      _execute_action: {
        suggested_key: {
          default: "Alt+Shift+G",
          mac: "Alt+Shift+G",
        },
        description: "Open PGP Tools",
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
