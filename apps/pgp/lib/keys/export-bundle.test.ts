import { beforeEach, describe, expect, it, vi } from "vitest";

import { downloadPublicKey } from "./export-bundle";
import { downloadText } from "../utils/download";

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
