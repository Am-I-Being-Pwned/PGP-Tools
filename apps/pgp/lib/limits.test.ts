/** File-size ceiling: a sanity bound, not the bomb guard (that is
 *  `decrypt_limit` in `gpg-wasm/src/limits.rs`). */

import { describe, expect, it } from "vitest";

import {
  MAX_FILE_BYTES,
  MAX_FILE_LABEL,
  oversizedFilesMessage,
  splitOversizedFiles,
} from "./limits";

function f(name: string, size: number) {
  return { name, size };
}

describe("splitOversizedFiles", () => {
  it("accepts ordinary files", () => {
    const files = [f("a.txt", 1024), f("b.pdf", 5 * 1024 * 1024)];
    expect(splitOversizedFiles(files)).toEqual({
      accepted: files,
      rejected: [],
    });
  });

  it("accepts a file of exactly the limit", () => {
    const { accepted, rejected } = splitOversizedFiles([
      f("exact.bin", MAX_FILE_BYTES),
    ]);
    expect(accepted).toHaveLength(1);
    expect(rejected).toHaveLength(0);
  });

  it("rejects one byte over the limit", () => {
    const { accepted, rejected } = splitOversizedFiles([
      f("over.bin", MAX_FILE_BYTES + 1),
    ]);
    expect(accepted).toHaveLength(0);
    expect(rejected).toHaveLength(1);
  });

  it("accepts a 1 GB file rather than refusing it on a guess", () => {
    const { accepted } = splitOversizedFiles([
      f("disk.img", 1024 * 1024 * 1024),
    ]);
    expect(accepted.map((a) => a.name)).toEqual(["disk.img"]);
  });

  it("rejects what cannot possibly work", () => {
    const { rejected } = splitOversizedFiles([f("huge.img", 5 * 1024 ** 3)]);
    expect(rejected.map((r) => r.name)).toEqual(["huge.img"]);
  });

  it("keeps the files it can when a drop is mixed", () => {
    const { accepted, rejected } = splitOversizedFiles([
      f("notes.txt", 100),
      f("huge.iso", MAX_FILE_BYTES * 8),
      f("keys.asc", 4096),
    ]);
    expect(accepted.map((a) => a.name)).toEqual(["notes.txt", "keys.asc"]);
    expect(rejected.map((r) => r.name)).toEqual(["huge.iso"]);
  });

  it("preserves order within each group", () => {
    const { accepted } = splitOversizedFiles([
      f("1", 1),
      f("big", MAX_FILE_BYTES + 1),
      f("2", 2),
      f("3", 3),
    ]);
    expect(accepted.map((a) => a.name)).toEqual(["1", "2", "3"]);
  });

  it("handles an empty drop", () => {
    expect(splitOversizedFiles([])).toEqual({ accepted: [], rejected: [] });
  });

  it("treats a zero-byte file as acceptable", () => {
    expect(splitOversizedFiles([f("empty", 0)]).accepted).toHaveLength(1);
  });
});

describe("oversizedFilesMessage", () => {
  it("is silent when nothing was rejected", () => {
    expect(oversizedFilesMessage([])).toBeNull();
  });

  it("names a single file and the limit", () => {
    const message = oversizedFilesMessage([{ name: "disk.img" }]);
    expect(message).toContain("disk.img");
    expect(message).toContain(MAX_FILE_LABEL);
    expect(message).toContain("file is");
  });

  it("names several files", () => {
    const message = oversizedFilesMessage([{ name: "a" }, { name: "b" }]);
    expect(message).toContain("a, b");
    expect(message).toContain("files are");
  });

  it("summarises a long list rather than printing all of it", () => {
    // A 40-file drop should not produce a 40-name error banner.
    const message = oversizedFilesMessage(
      Array.from({ length: 40 }, (_, i) => ({ name: `f${i}` })),
    );
    expect(message).toContain("f0, f1, f2 and 37 more");
    expect(message).not.toContain("f39");
  });
});

describe("MAX_FILE_BYTES", () => {
  it("is the wasm32 address space, not a judgement about file sizes", () => {
    // A platform fact; a smaller number needs a measurement to justify it.
    expect(MAX_FILE_BYTES).toBe(4 * 1024 * 1024 * 1024);
  });

  it("advertises the limit it actually enforces", () => {
    expect(MAX_FILE_LABEL).toBe("4 GB");
  });
});
