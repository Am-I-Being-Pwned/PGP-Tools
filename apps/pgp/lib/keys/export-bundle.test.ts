import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { PublicContactKey } from "../storage/contacts";
import { downloadText } from "../utils/download";
import {
  backupFileName,
  downloadPublicKey,
  downloadPublicKeysBundle,
} from "./export-bundle";

vi.mock("../utils/download", () => ({
  downloadText: vi.fn(),
}));

const lastCall = (): [string, string] => {
  const call = vi.mocked(downloadText).mock.lastCall;
  if (!call) throw new Error("downloadText was not called");
  return call;
};

describe("downloadPublicKey", () => {
  beforeEach(() => {
    vi.mocked(downloadText).mockClear();
  });

  it("slugs the display name into <slug>-public.asc", () => {
    downloadPublicKey("ARMOR", "Alice Example (work)");
    expect(lastCall()[1]).toBe("alice-example-work-public.asc");
  });

  it("uses the pem extension for CRX keys", () => {
    downloadPublicKey("PEM", "My Extension", "pem");
    expect(lastCall()[1]).toBe("my-extension-public.pem");
  });

  it("falls back to 'key' when the name has no usable characters", () => {
    downloadPublicKey("ARMOR", "///");
    expect(lastCall()[1]).toBe("key-public.asc");
  });

  it("caps long names without leaving a trailing dash", () => {
    downloadPublicKey("ARMOR", "a".repeat(39) + " b");
    const name = lastCall()[1];
    expect(name).toBe("a".repeat(39) + "-public.asc");
  });

  it("normalizes the key text to end with exactly one newline", () => {
    downloadPublicKey("ARMOR\n\n", "alice");
    expect(lastCall()[0]).toBe("ARMOR\n");
  });
});

// ─────────────────────────────────────────────────────────────────────
// The slug is built from a contact's DISPLAY NAME, which is
// attacker-influenced text: it comes from a User ID inside an imported
// certificate, and it lands in a filename. So the transform has to be
// TOTAL -- every possible display name yields a name that is safe,
// non-empty and bounded -- rather than merely tidy for the names we have
// happened to see.
// ─────────────────────────────────────────────────────────────────────

describe("downloadPublicKey: adversarial display names", () => {
  beforeEach(() => {
    vi.mocked(downloadText).mockClear();
  });

  it("collapses runs of punctuation into a single dash", () => {
    downloadPublicKey("ARMOR", "Alice <alice@example.com>");
    expect(lastCall()[1]).toBe("alice-alice-example-com-public.asc");
  });

  it("trims leading as well as trailing separators", () => {
    downloadPublicKey("ARMOR", "!!! Alice !!!");
    expect(lastCall()[1]).toBe("alice-public.asc");
  });

  it("emits no path separators from a name that contains them", () => {
    // The filename reaches the download layer; a slug that kept slashes
    // or dots would be a directory traversal waiting to happen.
    downloadPublicKey("ARMOR", "../../etc/passwd");
    const name = lastCall()[1];
    expect(name).toBe("etc-passwd-public.asc");
    expect(name).not.toMatch(/[/\\]/);
  });

  it.each([["日本語"], ["🔑🔑🔑"], ["   "], [""]])(
    "falls back to 'key' for %s, which slugifies to nothing",
    (name) => {
      // A file called "-public.asc" is a worse outcome than a generic one.
      downloadPublicKey("ARMOR", name);
      expect(lastCall()[1]).toBe("key-public.asc");
    },
  );

  it("bounds a pathological User ID at 40 characters", () => {
    downloadPublicKey("ARMOR", "a".repeat(500));
    expect(lastCall()[1]).toBe(`${"a".repeat(40)}-public.asc`);
  });

  it("uses the pub extension for an SSH recipient line", () => {
    // .pub is what every other tool on the machine expects that file to
    // be called.
    downloadPublicKey("ssh-ed25519 AAAA", "Alice", "pub");
    expect(lastCall()[1]).toBe("alice-public.pub");
  });
});

describe("backupFileName", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("dates the file by UTC day", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2025-01-31T23:30:00Z"));
    expect(backupFileName()).toBe("pgp-tools-keys-2025-01-31.asc");
  });
});

describe("downloadPublicKeysBundle", () => {
  function contact(armored: string): PublicContactKey {
    return {
      keyId: armored,
      userIds: ["x"],
      algorithm: "ed25519",
      armoredPublicKey: armored,
      addedAt: 1,
      lastUsedAt: 1,
    };
  }

  beforeEach(() => {
    vi.mocked(downloadText).mockClear();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("joins the keys with a blank line and returns the count", () => {
    const n = downloadPublicKeysBundle([contact("KEY-A"), contact("KEY-B")]);
    expect(n).toBe(2);
    expect(lastCall()[0]).toBe("KEY-A\n\nKEY-B\n");
  });

  it("writes under the dated backup filename", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2025-06-01T00:00:00Z"));
    downloadPublicKeysBundle([contact("KEY-A")]);
    expect(lastCall()[1]).toBe("pgp-tools-keys-2025-06-01.asc");
  });

  it("skips contacts holding no key material", () => {
    // A contact whose armored half is blank would otherwise contribute a
    // stray separator and inflate the reported count.
    const n = downloadPublicKeysBundle([
      contact("KEY-A"),
      contact("   "),
      contact(""),
    ]);
    expect(n).toBe(1);
    expect(lastCall()[0]).toBe("KEY-A\n");
  });

  it("returns zero for an empty selection", () => {
    expect(downloadPublicKeysBundle([])).toBe(0);
  });
});
