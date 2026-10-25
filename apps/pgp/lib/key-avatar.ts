/**
 * A key's face: a 16×16 pixel person drawn from its fingerprint.
 *
 * Each byte of the fingerprint picks one trait (backdrop, skin, hair
 * style and colour, eyes, mouth, facial hair, accessory, shirt), so the
 * same key always draws the same person and a swapped key looks like a
 * different one. It is a recognition aid only: a few million faces are
 * far too few to stand in for comparing the fingerprint itself, and the
 * UI must never present them as a check.
 *
 * Pure and synchronous so it can run during render; no network, no
 * secrets (fingerprints are public).
 */

export const AVATAR_SIZE = 16;

export interface KeyAvatar {
  /** Row-major, AVATAR_SIZE × AVATAR_SIZE CSS colours. */
  cells: string[];
}

const BGH = [20, 60, 100, 150, 200, 240, 285, 330];
const SHH = [0, 35, 70, 130, 180, 220, 265, 310];
const ACH = [15, 50, 90, 145, 195, 250, 290, 335];
const SKIN = ["#f6d5bd", "#e9b48c", "#c98a5e", "#9c6239", "#6f4226", "#4a2c18"];
const SKIN2 = [
  "#dfb79c",
  "#cf976f",
  "#ad7148",
  "#82502c",
  "#5a341d",
  "#3a2212",
];
const HAIR = [
  "#161616",
  "#3d2616",
  "#7a4b24",
  "#c48a3a",
  "#e8c66a",
  "#a8362a",
  "#dcdcdc",
  "#4f74d9",
  "#d05aa9",
  "#3fae84",
];
const EYE = ["#2b1d14", "#3b6fb6", "#3f8a55", "#8a6a2a", "#6b6b6b"];

const ok = (l: number, c: number, h: number) => `oklch(${l} ${c} ${h})`;

/**
 * The bytes a fingerprint stands for. OpenPGP fingerprints are hex; SSH
 * (age) recipients use OpenSSH's `SHA256:<base64>`. Anything else (or
 * too short to fill every trait) is stretched deterministically, so the
 * function is total.
 */
export function fingerprintBytes(fingerprint: string): number[] {
  const raw = fingerprint.trim();
  let bytes: number[] = [];
  const hex = raw.replace(/[\s:]/g, "");
  if (/^[0-9a-fA-F]+$/.test(hex) && hex.length % 2 === 0) {
    bytes = (hex.match(/../g) ?? []).map((x) => parseInt(x, 16));
  } else if (raw.startsWith("SHA256:")) {
    try {
      const b64 = raw.slice(7).replace(/-/g, "+").replace(/_/g, "/");
      const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
      bytes = Array.from(atob(padded), (c) => c.charCodeAt(0));
    } catch {
      bytes = [];
    }
  }
  if (bytes.length >= 14) return bytes;
  // FNV-1a over the string, re-seeded per byte: total and stable.
  const out: number[] = [];
  for (let i = 0; i < 20; i++) {
    let h = 0x811c9dc5 ^ i;
    for (let j = 0; j < raw.length; j++) {
      h ^= raw.charCodeAt(j);
      h = Math.imul(h, 0x01000193);
    }
    out.push((h >>> 24) & 0xff);
  }
  return out;
}

/**
 * Whether `id` is a whole fingerprint the face can be drawn from. A bare
 * 64-bit key id (what a signature names when we don't hold the key) is
 * not: a face hashed from it would not match the face the same key gets
 * once imported, and would look just as confident. Those get no face.
 */
export function hasKeyFace(id: string): boolean {
  const raw = id.trim();
  if (raw.startsWith("SHA256:")) return raw.length > 7;
  const hex = raw.replace(/[\s:]/g, "");
  if (/^[0-9a-fA-F]+$/.test(hex)) return hex.length >= 40;
  // Anything else that names a key whole (a CRX extension id) is stable.
  return raw.length >= 32;
}

export function keyAvatar(fingerprint: string): KeyAvatar {
  const b = fingerprintBytes(fingerprint);
  const at = (i: number) => b[i % b.length] ?? 0;
  const N = AVATAR_SIZE;

  const bgH = BGH[at(0) % 8] ?? 0;
  const bg = ok(0.36, 0.08, bgH);
  const pat = ok(0.42, 0.09, bgH);
  const texture = at(1) % 4;
  const g: string[][] = Array.from({ length: N }, (_, r) =>
    Array.from({ length: N }, (_, c) => {
      if (texture === 1 && (r + c) % 4 === 0) return pat;
      if (texture === 2 && r % 3 === 1 && c % 3 === 1) return pat;
      if (texture === 3 && c >= 8) return pat;
      return bg;
    }),
  );
  const set = (r: number, c: number, col: string) => {
    if (r >= 0 && r < N && c >= 0 && c < N) g[r][c] = col;
  };
  const row = (r: number, a: number, z: number, col: string) => {
    for (let c = a; c <= z; c++) set(r, c, col);
  };
  const pts = (list: [number, number][], col: string) => {
    for (const [r, c] of list) set(r, c, col);
  };

  const si = at(2) % 6;
  const skin = SKIN[si] ?? "#e9b48c";
  const shade = SKIN2[si] ?? "#cf976f";
  const hc = HAIR[at(4) % 10] ?? "#161616";
  const shH = SHH[at(10) % 8] ?? 0;
  const sh = ok(0.6, 0.15, shH);
  const sh2 = ok(0.47, 0.13, shH);
  const acH = ACH[at(9) % 8] ?? 0;
  const ac = ok(0.68, 0.16, acH);
  const ac2 = ok(0.5, 0.14, acH);
  const lip = "#7d3b33";

  // Body and shirt cut.
  row(12, 4, 11, sh);
  for (let r = 13; r <= 15; r++) row(r, 2, 13, sh);
  const cut = at(11) % 6;
  if (cut === 1) {
    row(13, 2, 13, sh2);
    row(15, 2, 13, sh2);
  }
  if (cut === 3) {
    row(12, 4, 11, sh2);
    pts(
      [
        [13, 6],
        [14, 6],
        [13, 9],
        [14, 9],
      ],
      "#efefef",
    );
  }
  if (cut === 4)
    pts(
      [
        [13, 9],
        [13, 10],
        [14, 9],
        [14, 10],
      ],
      ac,
    );

  // Neck and head.
  row(11, 6, 9, skin);
  if (cut === 2) {
    pts(
      [
        [12, 5],
        [12, 6],
        [12, 9],
        [12, 10],
      ],
      "#efefef",
    );
    pts(
      [
        [12, 7],
        [12, 8],
      ],
      skin,
    );
  } else if (cut === 5) {
    row(12, 6, 9, skin);
    pts(
      [
        [13, 7],
        [13, 8],
      ],
      skin,
    );
  } else
    pts(
      [
        [12, 7],
        [12, 8],
      ],
      skin,
    );
  for (let r = 3; r <= 10; r++) row(r, 4, 11, skin);
  pts(
    [
      [3, 4],
      [3, 11],
      [10, 4],
      [10, 11],
    ],
    bg,
  );
  pts(
    [
      [6, 3],
      [7, 3],
      [6, 12],
      [7, 12],
    ],
    skin,
  );

  // Facial hair that sits under the mouth.
  const face = at(7) % 8;
  if (face === 7) {
    for (let r = 9; r <= 10; r++)
      for (let c = 5; c <= 10; c++) if ((r + c) % 2) set(r, c, shade);
  }
  if (face === 5) {
    for (let r = 8; r <= 10; r++) row(r, 4, 11, hc);
    row(11, 6, 9, hc);
    pts(
      [
        [6, 4],
        [7, 4],
        [6, 11],
        [7, 11],
      ],
      hc,
    );
    pts(
      [
        [10, 4],
        [10, 11],
      ],
      bg,
    );
  }

  // Mouth.
  const m = at(6) % 5;
  if (m === 0)
    pts(
      [
        [8, 6],
        [9, 7],
        [9, 8],
        [8, 9],
      ],
      lip,
    );
  if (m === 1)
    pts(
      [
        [9, 7],
        [9, 8],
      ],
      lip,
    );
  if (m === 2) {
    pts(
      [
        [8, 6],
        [9, 6],
        [9, 9],
        [8, 9],
      ],
      lip,
    );
    pts(
      [
        [9, 7],
        [9, 8],
      ],
      "#f2f2f2",
    );
  }
  if (m === 3)
    pts(
      [
        [9, 7],
        [9, 8],
        [8, 9],
      ],
      lip,
    );
  if (m === 4)
    pts(
      [
        [9, 7],
        [9, 8],
        [10, 7],
        [10, 8],
      ],
      "#3b1a17",
    );
  if (face === 4) row(8, 6, 9, hc);
  if (face === 6) {
    row(10, 6, 9, hc);
    pts(
      [
        [11, 7],
        [11, 8],
      ],
      hc,
    );
  }

  // Eyes and brows.
  pts(
    [
      [7, 6],
      [7, 9],
    ],
    EYE[at(5) % 5] ?? "#2b1d14",
  );
  pts(
    [
      [5, 5],
      [5, 6],
      [5, 9],
      [5, 10],
    ],
    hc === "#dcdcdc" ? "#b5b5b5" : hc,
  );

  // Hair.
  const st = at(3) % 11;
  const cap = () => {
    row(2, 5, 10, hc);
    row(3, 4, 11, hc);
    pts(
      [
        [4, 4],
        [4, 11],
      ],
      hc,
    );
  };
  const short = () => {
    cap();
    pts(
      [
        [4, 5],
        [4, 10],
      ],
      hc,
    );
  };
  if (st === 0) short();
  if (st === 1) {
    cap();
    for (let r = 3; r <= 13; r++)
      pts(
        [
          [r, 3],
          [r, 12],
        ],
        hc,
      );
    for (let r = 4; r <= 6; r++)
      pts(
        [
          [r, 4],
          [r, 11],
        ],
        hc,
      );
  }
  if (st === 2) {
    short();
    row(1, 6, 9, hc);
    row(0, 7, 8, hc);
  }
  if (st === 3) {
    cap();
    row(1, 5, 10, hc);
    pts(
      [
        [0, 5],
        [0, 8],
        [0, 10],
      ],
      hc,
    );
  }
  if (st === 5) {
    row(0, 5, 10, hc);
    row(1, 3, 12, hc);
    row(2, 2, 13, hc);
    for (let r = 3; r <= 7; r++)
      pts(
        [
          [r, 2],
          [r, 3],
          [r, 12],
          [r, 13],
        ],
        hc,
      );
    row(3, 4, 11, hc);
    pts(
      [
        [4, 4],
        [4, 11],
      ],
      hc,
    );
  }
  if (st === 6) {
    cap();
    row(4, 4, 9, hc);
    set(5, 4, hc);
  }
  if (st === 7) {
    cap();
    row(4, 4, 6, hc);
    set(5, 4, hc);
  }
  if (st === 8) {
    short();
    pts(
      [
        [4, 3],
        [4, 12],
      ],
      hc,
    );
    for (let r = 5; r <= 9; r++)
      pts(
        [
          [r, 2],
          [r, 13],
        ],
        hc,
      );
    pts(
      [
        [5, 2],
        [5, 13],
      ],
      ac,
    );
  }
  if (st === 9) {
    for (let r = 0; r <= 3; r++) row(r, 7, 8, hc);
  }
  if (st === 10) {
    row(3, 5, 10, hc);
    pts(
      [
        [4, 4],
        [4, 11],
      ],
      hc,
    );
  }

  // Accessories.
  const a = at(8) % 10;
  if (a === 3) {
    row(6, 5, 10, "#1d1d1d");
    pts(
      [
        [7, 5],
        [7, 7],
        [7, 8],
        [7, 10],
      ],
      "#1d1d1d",
    );
  }
  if (a === 4) {
    row(6, 5, 10, "#111111");
    row(7, 5, 10, "#111111");
    pts(
      [
        [6, 6],
        [6, 9],
      ],
      "#4f6b7c",
    );
  }
  if (a === 5) {
    row(0, 7, 8, "#f2f2f2");
    row(1, 5, 10, ac);
    row(2, 4, 11, ac);
    row(3, 4, 11, ac);
    row(4, 4, 11, ac2);
  }
  if (a === 6) {
    row(2, 5, 10, ac);
    row(3, 4, 11, ac);
    row(4, 4, 11, ac);
    row(5, 4, 12, ac2);
  }
  if (a === 7) {
    row(1, 5, 10, "#2b2b2b");
    pts(
      [
        [2, 4],
        [2, 11],
        [3, 3],
        [3, 12],
        [4, 3],
        [4, 12],
      ],
      "#2b2b2b",
    );
    for (let r = 5; r <= 8; r++)
      pts(
        [
          [r, 2],
          [r, 3],
          [r, 12],
          [r, 13],
        ],
        "#2b2b2b",
      );
    pts(
      [
        [6, 2],
        [7, 2],
        [6, 13],
        [7, 13],
      ],
      ac,
    );
  }
  if (a === 8) set(8, 3, "#e7c64b");
  if (a === 9) row(4, 4, 11, ac);

  return { cells: g.flat() };
}
