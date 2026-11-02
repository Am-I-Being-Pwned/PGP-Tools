import { describe, expect, it } from "vitest";

import {
  initialWorkspaceState,
  inputIsAge,
  resolveKeyId,
  textFacts,
  workspaceReducer,
  zeroizeResultBytes,
  type Outcome,
  type WorkspaceEvent,
  type WorkspaceState,
} from "~/components/workspace/workspace-state";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import type { FileResult } from "~/lib/utils/download";

const reduce = (s: WorkspaceState, ...events: WorkspaceEvent[]) =>
  events.reduce(workspaceReducer, s);

const SIGNED = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nhi";
const MESSAGE = "-----BEGIN PGP MESSAGE-----\n\nabc";
const PUBLIC = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nabc";
const PRIVATE = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nabc";

const file = (name: string) => new File(["x"], name);
const finished = (s: WorkspaceState, outcome: Outcome): WorkspaceState =>
  workspaceReducer(s, { type: "finished", outcome, staged: s.staged });

/** A state with a completed run that left everything behind. */
function withResults(s = initialWorkspaceState): WorkspaceState {
  const done = finished(reduce(s, { type: "started" }), {
    kind: "done",
    files: [{ name: "a", data: new Uint8Array([1]) }],
    status: "ok",
  });
  return reduce(done, { type: "output", len: 5, publicKey: true });
}

describe("textFacts", () => {
  it("keeps only facts, and checks blankness without trimming", () => {
    expect(textFacts("  \n")).toMatchObject({ len: 3, nonBlank: false });
    expect(textFacts("hi")).toMatchObject({ len: 2, nonBlank: true });
  });

  it("the earliest message header decides the armor", () => {
    expect(textFacts(`${SIGNED}\n${MESSAGE}`).armor).toBe("verify");
    expect(textFacts(MESSAGE).armor).toBe("decrypt");
  });

  it("a private key wins; a key quoted in a message is not a key", () => {
    expect(textFacts(`${PRIVATE}\n${MESSAGE}`).key).toBe("private");
    expect(textFacts(`${MESSAGE}\n${PUBLIC}`).key).toBeNull();
    expect(textFacts(PUBLIC).key).toBe("public");
  });
});

describe("edited", () => {
  it("nudges the mode only when armor arrives", () => {
    const pasted = reduce(initialWorkspaceState, {
      type: "edited",
      text: textFacts(SIGNED),
    });
    expect(pasted.mode).toBe("verify");
    // The user goes back to Encrypt with the signed text still there.
    const back = reduce(
      pasted,
      { type: "mode-picked", mode: "encrypt" },
      { type: "edited", text: textFacts(`${SIGNED}!`) },
    );
    expect(back.mode).toBe("encrypt");
  });

  it("never nudges for a private key", () => {
    const s = reduce(initialWorkspaceState, {
      type: "edited",
      text: textFacts(`${PRIVATE}\n${MESSAGE}`),
    });
    expect(s.mode).toBe("encrypt");
    expect(s.input.key).toBe("private");
  });

  it("keeps attachments in encrypt, replaces files elsewhere", () => {
    const staged = reduce(initialWorkspaceState, {
      type: "dropped",
      files: [file("a.txt")],
      encrypted: false,
      oversized: null,
    });
    const typed = { type: "edited", text: textFacts("hi") } as const;
    expect(reduce(staged, typed).files).toHaveLength(1);
    const signing = reduce(staged, { type: "mode-picked", mode: "sign" });
    expect(reduce(signing, typed).files).toHaveLength(0);
  });

  it("cancels a pending auto-run and bumps the staged generation", () => {
    const opened = reduce(initialWorkspaceState, {
      type: "opened",
      mode: "decrypt",
      text: textFacts(MESSAGE),
      autoRun: "decrypt",
    });
    const edited = reduce(opened, {
      type: "edited",
      text: textFacts(`${MESSAGE}x`),
    });
    expect(edited.autoRun).toBeNull();
    expect(edited.staged).toBeGreaterThan(opened.staged);
  });
});

describe("resetResults (one rule, every path)", () => {
  const paths: WorkspaceEvent[] = [
    { type: "edited", text: textFacts("x") },
    { type: "reset-results" },
    { type: "reset-all" },
    { type: "mode-picked", mode: "decrypt" },
    { type: "recipients", ids: ["A"] },
    { type: "key-picked", keyId: "K" },
    { type: "zip-files", on: false },
    { type: "files-cleared" },
    { type: "password-set", password: "" },
    { type: "started" },
  ];
  for (const event of paths) {
    it(`${event.type} clears result, output, prompt and verdict`, () => {
      const s = reduce(withResults(), { type: "prompted", kind: "message" });
      const next = workspaceReducer(s, event);
      expect(next.result).toEqual({ status: null, verdict: null, files: [] });
      expect(next.output.len).toBe(0);
      expect(next.output.version).toBeGreaterThan(s.output.version);
      expect(next.prompt).toBeNull();
      expect(next.run.kind).toBe(event.type === "started" ? "running" : "idle");
    });
  }

  it("never stops a run in flight", () => {
    const running = reduce(initialWorkspaceState, { type: "started" });
    expect(
      reduce(running, { type: "edited", text: textFacts("x") }).run.kind,
    ).toBe("running");
  });

  it("a completed run switches mode with a full reset", () => {
    const s = reduce(
      withResults(),
      { type: "recipients", ids: ["A"] },
      { type: "started" },
    );
    const done = finished(s, { kind: "done" });
    const next = reduce(done, { type: "mode-picked", mode: "sign" });
    expect(next.recipientIds).toEqual([]);
    expect(next.mode).toBe("sign");
  });
});

describe("finished", () => {
  it("discards a run whose input moved while it ran", () => {
    const started = reduce(initialWorkspaceState, { type: "started" });
    const moved = reduce(started, {
      type: "dropped",
      files: [file("b")],
      encrypted: false,
      oversized: null,
    });
    const next = workspaceReducer(moved, {
      type: "finished",
      staged: started.staged,
      outcome: { kind: "done", status: "verified" },
    });
    expect(next.run.kind).toBe("idle");
    expect(next.result.status).toBeNull();
  });

  it("a prompt replaces any other prompt, and rejection keeps it up", () => {
    const s = finished(reduce(initialWorkspaceState, { type: "started" }), {
      kind: "prompt",
      prompt: "message",
    });
    expect(s.prompt).toEqual({ kind: "message", value: "", error: null });
    const typed = reduce(
      s,
      { type: "prompt-typed", value: "pw" },
      { type: "submitted" },
    );
    expect(typed.run.kind).toBe("running");
    const rejected = finished(typed, { kind: "rejected", message: "wrong" });
    expect(rejected.prompt).toEqual({
      kind: "message",
      value: "pw",
      error: "wrong",
    });
    expect(rejected.run.kind).toBe("idle");
  });

  it("done closes the prompt and spends the message password", () => {
    const s = reduce(
      initialWorkspaceState,
      { type: "password-set", password: "correct horse" },
      { type: "started" },
    );
    const done = finished(s, { kind: "done", spentPassword: true });
    expect(done.encryptPassword).toBe("");
    expect(done.run.kind).toBe("done");
  });
});

describe("dropped", () => {
  it("replaces a same-named file and flips encrypt to decrypt for ciphertext", () => {
    const first = file("release.asc");
    const second = file("release.asc");
    const s = reduce(
      initialWorkspaceState,
      { type: "edited", text: textFacts("note") },
      { type: "dropped", files: [first], encrypted: true, oversized: null },
      { type: "dropped", files: [second], encrypted: true, oversized: null },
    );
    expect(s.files).toEqual([second]);
    expect(s.mode).toBe("decrypt");
    expect(s.input.len).toBe(0);
  });

  it("an all-oversized drop leaves the workspace and reports why", () => {
    const s = reduce(initialWorkspaceState, {
      type: "edited",
      text: textFacts("keep"),
    });
    const next = reduce(s, {
      type: "dropped",
      files: [],
      encrypted: false,
      oversized: "too big",
    });
    expect(next.input.len).toBe(4);
    expect(next.run).toEqual({ kind: "error", error: { message: "too big" } });
  });

  it("a partial drop stages what it can and still reports", () => {
    const next = reduce(initialWorkspaceState, {
      type: "dropped",
      files: [file("a")],
      encrypted: false,
      oversized: "skipped b",
    });
    expect(next.files).toHaveLength(1);
    expect(next.run.kind).toBe("error");
  });

  it("text dropped beside attachments in encrypt stays", () => {
    const next = reduce(
      initialWorkspaceState,
      { type: "edited", text: textFacts("note") },
      {
        type: "dropped",
        files: [file("a")],
        encrypted: false,
        oversized: null,
      },
    );
    expect(next.input.len).toBe(4);
  });
});

describe("derived", () => {
  const key = (keyId: string, kind?: "ssh") =>
    ({ keyId, ...(kind ? { kind } : {}) }) as unknown as ProtectedKeyBlob;
  const keys = [key("PGP1"), key("SSH1", "ssh"), key("PGP2")];

  it("follows the default until the user picks, and drops an invalid pick", () => {
    const base = { mode: "encrypt" as const, keyPick: null, age: false };
    expect(resolveKeyId(base, keys, "PGP2")).toBe("PGP2");
    expect(resolveKeyId({ ...base, keyPick: "PGP1" }, keys, "PGP2")).toBe(
      "PGP1",
    );
    expect(resolveKeyId({ ...base, keyPick: "GONE" }, keys, "PGP2")).toBe(
      "PGP2",
    );
  });

  it("narrows to OpenPGP for sign and to SSH for an age decrypt", () => {
    expect(
      resolveKeyId({ mode: "sign", keyPick: "SSH1", age: false }, keys, "SSH1"),
    ).toBe("PGP1");
    expect(
      resolveKeyId({ mode: "decrypt", keyPick: "PGP1", age: true }, keys, null),
    ).toBe("SSH1");
    // The pick comes back when the mode no longer rules it out.
    expect(
      resolveKeyId(
        { mode: "decrypt", keyPick: "SSH1", age: false },
        keys,
        null,
      ),
    ).toBe("SSH1");
  });

  it("age input is the text or a .age file", () => {
    const s = reduce(initialWorkspaceState, {
      type: "dropped",
      files: [file("m.AGE")],
      encrypted: true,
      oversized: null,
    });
    expect(inputIsAge(s)).toBe(true);
  });
});

// The part of `wipePlaintext` for the decrypted content that must be
// render state; see tests/e2e/draft-memory.spec.ts for the end-to-end proof.
describe("zeroizeResultBytes", () => {
  const bytesOf = (s: string) => new TextEncoder().encode(s);

  it("overwrites the binary result and every file result in place", () => {
    const secret = bytesOf("decrypted payload");
    const results: FileResult[] = [
      { name: "a.txt", data: bytesOf("first") },
      { name: "b.txt", data: bytesOf("second") },
    ];
    zeroizeResultBytes(secret, results);
    expect(secret.every((b) => b === 0)).toBe(true);
    for (const r of results) expect(r.data.every((b) => b === 0)).toBe(true);
    expect(results.map((r) => r.name)).toEqual(["a.txt", "b.txt"]);
  });

  it("wipes only the view's own window of a shared buffer", () => {
    const backing = new Uint8Array(8).fill(0xff);
    zeroizeResultBytes(backing.subarray(2, 5), []);
    expect(Array.from(backing)).toEqual([255, 255, 0, 0, 0, 255, 255, 255]);
  });

  it("tolerates a detached buffer and still wipes the rest", () => {
    const detached = new Uint8Array(4).fill(7);
    structuredClone(detached.buffer, { transfer: [detached.buffer] });
    const alsoSecret = bytesOf("still reachable");
    expect(() =>
      zeroizeResultBytes(detached, [{ name: "x", data: alsoSecret }]),
    ).not.toThrow();
    expect(alsoSecret.every((b) => b === 0)).toBe(true);
  });
});
