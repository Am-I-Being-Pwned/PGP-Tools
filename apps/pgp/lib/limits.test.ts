/**
 * The file-size ceiling.
 *
 * This is a SANITY bound, not the bomb guard -- that is a ratio, and it
 * lives in `gpg-wasm/src/lib.rs` (`decrypt_limit`). What is pinned here
 * is the handling around the bound, which is where the user-visible
 * behaviour is:
 *
 *  - it partitions rather than rejecting the whole drop, so one oversized
 *    file in a folder does not discard the rest;
 *  - a file of EXACTLY the limit is allowed, so the number in the error
 *    message means the same thing to a user as it does in the code;
 *  - the message names the offending files, because "a file was too
 *    large" in a multi-file drop leaves the user guessing;
 *  - and the bound stays a platform fact rather than drifting back to a
 *    hand-picked number that refuses files which actually work.
 */

import { describe, expect, it } from "vitest";

import {
  MAX_FILE_BYTES,
  MAX_FILE_LABEL,
  oversizedFilesMessage,
  splitOversizedFiles,
} from "./limits";

/** Just the shape the rule reads -- no DOM, no real File. */
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
    // Strictly greater, so the advertised number is inclusive.
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
    // The ceiling is a fact about wasm32's address space, not an opinion
    // about what a user should be doing. Whether a 1 GB file actually
    // completes depends on the machine; refusing it here would decide
    // that in advance and be wrong on the machines where it works.
    const { accepted } = splitOversizedFiles([
      f("disk.img", 1024 * 1024 * 1024),
    ]);
    expect(accepted.map((a) => a.name)).toEqual(["disk.img"]);
  });

  it("rejects what cannot possibly work", () => {
    // Past 4 GiB there is no address space for it, on any machine.
    const { rejected } = splitOversizedFiles([f("huge.img", 5 * 1024 ** 3)]);
    expect(rejected.map((r) => r.name)).toEqual(["huge.img"]);
  });

  it("keeps the files it can when a drop is mixed", () => {
    // Dragging a folder that happens to contain one huge file must not
    // throw away everything else in it.
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
    // Empty is a legitimate thing to encrypt, and it is certainly not a
    // memory hazard.
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
    // Pinned as a platform fact. If this ever becomes a smaller,
    // hand-picked number again, it needs the measurement to justify it --
    // the last one was a guess and refused files that worked.
    expect(MAX_FILE_BYTES).toBe(4 * 1024 * 1024 * 1024);
  });

  it("advertises the limit it actually enforces", () => {
    // The label is what the user reads; drift between the two is how a
    // "4 GB" limit ends up rejecting a 3 GB file.
    expect(MAX_FILE_LABEL).toBe("4 GB");
  });
});
