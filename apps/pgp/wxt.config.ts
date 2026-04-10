import tailwindcss from "@tailwindcss/vite";
import wasm from "vite-plugin-wasm";
import { defineConfig } from "wxt";

export default defineConfig({
  modules: ["@wxt-dev/module-react"],
  manifest: () => ({
    name: "PGP Tools - Encrypt, Decrypt & Sign",
    short_name: "PGP Tools",
    description:
      "Encrypt, decrypt, sign, and verify messages with PGP. Drag-and-drop files and manage keys.",
    permissions: ["sidePanel", "contextMenus", "storage"],
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
    content_security_policy: {
      extension_pages: [
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
      ].join("; ") + ";",
    },
  }),
  vite: () => ({
    plugins: [tailwindcss(), wasm()],
    server: { port: 3004 },
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
