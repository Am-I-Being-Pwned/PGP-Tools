/**
 * Writes parts/avatar-<name>.html: a key's real KeyAvatar face as an
 * inline SVG, drawn by the extension's own lib/key-avatar so the tile
 * shows the face the app shows for the same key. Re-run if the avatar
 * drawing changes:
 *
 *     npx tsx assets/store-listing/promo/avatar.ts
 */
import { writeFileSync } from "node:fs";
import path from "node:path";

import { AVATAR_SIZE, keyAvatar } from "../../../apps/pgp/lib/key-avatar";

// The `standard` e2e fixture (apps/pgp/e2e/keys.ts), the same Alice the
// panel capture picks as a recipient on slide a.
const FACES = { alice: "1D2DFAC2C18051E9C11037A6E3AA99801E250E69" };

for (const [name, fingerprint] of Object.entries(FACES)) {
  const { cells } = keyAvatar(fingerprint);
  const rects: string[] = [];
  for (let y = 0; y < AVATAR_SIZE; y++) {
    let x = 0;
    while (x < AVATAR_SIZE) {
      const fill = cells[y * AVATAR_SIZE + x];
      let w = 1;
      while (x + w < AVATAR_SIZE && cells[y * AVATAR_SIZE + x + w] === fill)
        w++;
      rects.push(`<rect x="${x}" y="${y}" width="${w}" height="1" fill="${fill}"/>`);
      x += w;
    }
  }
  const svg = `<svg class="avatar" aria-hidden="true" viewBox="0 0 ${AVATAR_SIZE} ${AVATAR_SIZE}" shape-rendering="crispEdges">${rects.join("")}</svg>\n`;
  writeFileSync(path.join(import.meta.dirname, "parts", `avatar-${name}.html`), svg);
}
