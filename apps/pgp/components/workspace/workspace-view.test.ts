import { describe, expect, it } from "vitest";

import type { FileResult } from "~/lib/utils/download";
import { initialWorkspaceState, type WorkspaceState } from "./workspace-state";
import { deriveWorkspaceView } from "./workspace-view";

const flags = {
  canCrxSign: false,
  passwordReady: false,
  crxSigningEnabled: false,
};
const state = (over: Partial<WorkspaceState>): WorkspaceState => ({
  ...initialWorkspaceState,
  ...over,
});
const done = { kind: "done" } as const;
const withOutput = { ...initialWorkspaceState.output, len: 5 };
const crxFile = {
  name: "ext.crx",
  data: new Uint8Array(),
} as unknown as FileResult;
const verdict = (tone: string) =>
  ({ tone }) as unknown as NonNullable<WorkspaceState["result"]["verdict"]>;

describe("deriveWorkspaceView", () => {
  it("encrypt can run only with a recipient or a ready password", () => {
    expect(deriveWorkspaceView(state({ mode: "encrypt" }), flags).canRun).toBe(
      false,
    );
    expect(
      deriveWorkspaceView(
        state({ mode: "encrypt", recipientIds: ["k"] }),
        flags,
      ).canRun,
    ).toBe(true);
    expect(
      deriveWorkspaceView(state({ mode: "encrypt" }), {
        ...flags,
        passwordReady: true,
      }).canRun,
    ).toBe(true);
  });

  it("a password-only or unencrypted message needs no private key", () => {
    const pw = state({
      mode: "decrypt",
      messageEncryption: { password: true, publicKey: false, encrypted: true },
    });
    expect(deriveWorkspaceView(pw, flags).needsPrivateKey).toBe(false);
    const plain = state({
      mode: "decrypt",
      messageEncryption: { encrypted: false },
    } as Partial<WorkspaceState>);
    expect(deriveWorkspaceView(plain, flags).needsPrivateKey).toBe(false);
    expect(
      deriveWorkspaceView(state({ mode: "sign" }), flags).needsPrivateKey,
    ).toBe(true);
  });

  it("offers Reply only on a decrypt whose signer is known", () => {
    const base = { mode: "decrypt", run: done, output: withOutput } as const;
    const known = state({
      ...base,
      result: { ...initialWorkspaceState.result, verdict: verdict("success") },
    });
    const amber = state({
      ...base,
      result: { ...initialWorkspaceState.result, verdict: verdict("warning") },
    });
    expect(deriveWorkspaceView(known, flags).canReply).toBe(true);
    expect(deriveWorkspaceView(amber, flags).canReply).toBe(false);
  });

  it("a finished run hides the main action, except verify's", () => {
    const enc = state({ mode: "encrypt", recipientIds: ["k"], run: done });
    expect(deriveWorkspaceView(enc, flags).canRun).toBe(false);
    const ver = state({ mode: "verify", run: done });
    expect(deriveWorkspaceView(ver, flags).canRun).toBe(true);
  });

  it("verify has nothing to download; a CRX result is the CRX", () => {
    const ver = state({ mode: "verify", run: done, output: withOutput });
    expect(deriveWorkspaceView(ver, flags).hasDownload).toBe(false);
    const crx = state({
      mode: "sign",
      run: done,
      result: { ...initialWorkspaceState.result, files: [crxFile] },
    });
    const v = deriveWorkspaceView(crx, flags);
    expect(v.crxResult).toBe(crxFile);
    expect(v.hasDownload).toBe(true);
  });

  it("CRX signing shows only with a key, a zip, and no pick of PGP", () => {
    const zip = state({ mode: "sign", isExtensionZip: true });
    expect(deriveWorkspaceView(zip, flags).showCrxSign).toBe(false);
    const on = { ...flags, canCrxSign: true };
    expect(deriveWorkspaceView(zip, on).showCrxSign).toBe(true);
    expect(
      deriveWorkspaceView(state({ ...zip, signKindPick: "pgp" }), on)
        .showCrxSign,
    ).toBe(false);
  });
});
