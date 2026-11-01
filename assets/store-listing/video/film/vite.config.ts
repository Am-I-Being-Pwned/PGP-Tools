import { createReadStream, existsSync, statSync } from "node:fs";
import path from "node:path";
import type { Connect, Plugin } from "vite";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The film reads its pictures straight out of assets/store-listing (the
// real panel captures in ../ui, the fonts, the icon) under /sl/, so nothing
// is copied and a fresh capture shows up on the next render.
const ROOT = path.resolve(import.meta.dirname, "../..");
// The store badges live in the repo's .github folder, served under /gh/.
const GH = path.resolve(import.meta.dirname, "../../../../.github");
const TYPES: Record<string, string> = { ".png": "image/png", ".woff2": "font/woff2", ".asc": "text/plain", ".js": "text/javascript" };

function storeListing(): Plugin {
  const serve: Connect.NextHandleFunction = (req, res, next) => {
    const mount = req.url?.startsWith("/sl/") ? ROOT : req.url?.startsWith("/gh/") ? GH : null;
    if (!mount || !req.url) return next();
    const file = path.join(mount, decodeURIComponent(req.url.slice(4).split("?")[0]));
    if (!file.startsWith(mount) || !existsSync(file) || !statSync(file).isFile()) return next();
    res.setHeader("Content-Type", TYPES[path.extname(file)] ?? "application/octet-stream");
    createReadStream(file).pipe(res);
  };
  return {
    name: "store-listing",
    configureServer: (s) => void s.middlewares.use(serve),
    configurePreviewServer: (s) => void s.middlewares.use(serve),
  };
}

export default defineConfig({ base: "./", plugins: [react(), storeListing()] });
