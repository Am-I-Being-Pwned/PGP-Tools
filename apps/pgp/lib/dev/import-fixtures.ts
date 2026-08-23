import type { IncomingKey } from "../import/types";
import type { KeyDetails, KeyInfo } from "../pgp/types";

/**
 * DEV-ONLY placeholder keys for the import-flow harness. Reachable only
 * from the Developer section of Settings, which is gated behind
 * `import.meta.env.DEV` and tree-shaken out of production builds.
 *
 * These are hand-written metadata objects, not real certificates: the
 * preview panel is presentational (it takes parsed KeyInfo/KeyDetails,
 * never armor), so the whole flow can be reviewed before any parsing is
 * wired up -- and no key material, real or generated, lands in the repo.
 */

const DAY = 24 * 60 * 60 * 1000;
/** Fixed epoch so the harness renders the same dates every run. */
const NOW = Date.UTC(2026, 7, 23);

const FP_ALICE = "3A9E1F5C7B2D48E6A0C1938574FD62B0E4A75C11";
const FP_BOB = "B71C4D0928EF3A65D14C88790BAE2F3160D95E77";
const FP_CAROL = "5D2F80A31C9B47E6F0A25D8C34917BE6D0F2A488";

function info(over: Partial<KeyInfo> & Pick<KeyInfo, "keyId">): KeyInfo {
  return {
    userIds: ["Alice Example <alice@example.com>"],
    algorithm: "ed25519",
    createdAt: NOW - 400 * DAY,
    expiresAt: NOW + 500 * DAY,
    isPrivate: false,
    usableForEncryption: true,
    usableForSigning: true,
    ...over,
  };
}

function details(fingerprint: string, over?: Partial<KeyDetails>): KeyDetails {
  return {
    truncated: false,
    keys: [
      {
        fingerprint,
        keyId: fingerprint.slice(-16),
        algorithm: "ed25519",
        createdAt: NOW - 400 * DAY,
        expiresAt: NOW + 500 * DAY,
        isPrimary: true,
        canSign: true,
        canEncrypt: false,
        canCertify: true,
        canAuthenticate: false,
        status: "active",
      },
      {
        fingerprint: fingerprint.slice(0, 20) + "9F4C11D0E8B37A62C540",
        keyId: "9F4C11D0E8B37A62",
        algorithm: "cv25519",
        createdAt: NOW - 400 * DAY,
        expiresAt: NOW + 500 * DAY,
        isPrimary: false,
        canSign: false,
        canEncrypt: true,
        canCertify: false,
        canAuthenticate: false,
        status: "active",
      },
    ],
    ...over,
  };
}

export interface ImportScenario {
  id: string;
  label: string;
  hint: string;
  incoming: IncomingKey;
}

export const IMPORT_SCENARIOS: ImportScenario[] = [
  {
    id: "new-contact",
    label: "New contact",
    hint: "The common case: a public key you've never seen.",
    incoming: {
      keyId: FP_ALICE,
      kind: "public",
      status: "new",
      userIds: [
        "Alice Example <alice@example.com>",
        "Alice Example <alice@work.example>",
      ],
      info: info({
        keyId: FP_ALICE,
        userIds: [
          "Alice Example <alice@example.com>",
          "Alice Example <alice@work.example>",
        ],
      }),
      details: details(FP_ALICE),
      changes: [],
      publicArmored: "",
    },
  },
  {
    id: "update",
    label: "Update (expiry extended)",
    hint: "Same fingerprint, cert has moved on -- imports as an update.",
    incoming: {
      keyId: FP_ALICE,
      kind: "public",
      status: "update",
      userIds: ["Alice Example <alice@example.com>"],
      info: info({ keyId: FP_ALICE, expiresAt: NOW + 900 * DAY }),
      details: details(FP_ALICE),
      changes: ["New expiry: 8 February 2029", "1 new user ID"],
      existingAddedAt: NOW - 120 * DAY,
      publicArmored: "",
    },
  },
  {
    id: "duplicate",
    label: "Already imported",
    hint: "Byte-identical to a stored key -- in the real flow this never opens a panel.",
    incoming: {
      keyId: FP_BOB,
      kind: "public",
      status: "duplicate",
      userIds: ["Bob Example <bob@example.com>"],
      info: info({
        keyId: FP_BOB,
        userIds: ["Bob Example <bob@example.com>"],
      }),
      details: details(FP_BOB),
      changes: [],
      existingAddedAt: NOW - 30 * DAY,
      publicArmored: "",
    },
  },
  {
    id: "rejected",
    label: "Rejected (expired)",
    hint: "Unusable key: the health banner and the reason, no import button.",
    incoming: {
      keyId: FP_CAROL,
      kind: "public",
      status: "rejected",
      userIds: ["Carol Example <carol@example.com>"],
      info: info({
        keyId: FP_CAROL,
        userIds: ["Carol Example <carol@example.com>"],
        expiresAt: NOW - 60 * DAY,
        usableForEncryption: false,
        usableForSigning: false,
        policyError: "The key expired on 24 June 2026.",
      }),
      details: details(FP_CAROL, {
        keys: details(FP_CAROL).keys.map((k) => ({
          ...k,
          status: "expired" as const,
          expiresAt: NOW - 60 * DAY,
        })),
      }),
      changes: [],
      rejection:
        "This key expired on 24 June 2026. Ask the owner for their current key.",
      publicArmored: "",
    },
  },
  {
    id: "flagged",
    label: "New, but flagged (SHA-1)",
    hint: "Importable, with a security warning shown inline.",
    incoming: {
      keyId: FP_CAROL,
      kind: "public",
      status: "new",
      userIds: ["Carol Example <carol@example.com>"],
      info: info({
        keyId: FP_CAROL,
        userIds: ["Carol Example <carol@example.com>"],
        algorithm: "rsa2048",
      }),
      details: details(FP_CAROL),
      changes: [],
      securityWarning:
        "This key relies on a SHA-1 binding signature, which is no longer considered secure.",
      publicArmored: "",
    },
  },
  {
    id: "private",
    label: "Private key",
    hint: "Preview first, then the protect step -- button reads Continue.",
    incoming: {
      keyId: FP_ALICE,
      kind: "private",
      status: "new",
      userIds: ["Alice Example <alice@example.com>"],
      info: info({ keyId: FP_ALICE, isPrivate: true }),
      details: details(FP_ALICE),
      changes: [],
      publicArmored: "",
    },
  },
  {
    id: "sign-only",
    label: "Sign-only contact",
    hint: "Usable, but you can't encrypt to it -- warning banner.",
    incoming: {
      keyId: FP_BOB,
      kind: "public",
      status: "new",
      userIds: ["Bob Example <bob@example.com>"],
      info: info({
        keyId: FP_BOB,
        userIds: ["Bob Example <bob@example.com>"],
        usableForEncryption: false,
      }),
      details: details(FP_BOB, {
        keys: [details(FP_BOB).keys[0]],
      }),
      changes: [],
      publicArmored: "",
    },
  },
];
