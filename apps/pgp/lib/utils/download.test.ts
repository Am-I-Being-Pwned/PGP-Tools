/**
 * @vitest-environment jsdom
 *
 * Download helpers.
 *
 * The interesting half of this module is `saveCrxViaPrompt`, and what it
 * needs pinned is not "does it call chrome.downloads" but the RESULT
 * MAPPING, because each outcome drives a different UI:
 *
 *  - "cancelled" means the user said no -- stay quiet;
 *  - "blocked" means Chrome refused (disk full, AV, policy) -- offer the
 *    drag-out fallback;
 *  - "denied" means the optional permission was refused;
 *  - "unsupported" means the namespace isn't there at all.
 *
 * Collapsing any two of those loses a distinct piece of UI behaviour, and
 * the interrupted-download case is the easiest to get wrong: an AV
 * interruption and a user cancel arrive through the SAME callback and are
 * told apart only by the `USER_` prefix on the reason.
 *
 * Also pinned: the permission request swallows the "needs a user gesture"
 * throw. That path is hit on every auto-save after an async sign, and an
 * unhandled rejection there surfaces as a crash rather than a fallback.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  downloadBinary,
  downloadBlob,
  downloadResults,
  downloadText,
  saveCrxViaPrompt,
} from "./download";

// ── DOM / object-URL plumbing jsdom doesn't ship ─────────────────────

let created: string[];
let revoked: string[];
let clicked: HTMLAnchorElement[];

function stubObjectUrls() {
  created = [];
  revoked = [];
  let n = 0;
  URL.createObjectURL = vi.fn(() => {
    const url = `blob:test/${n++}`;
    created.push(url);
    return url;
  });
  URL.revokeObjectURL = vi.fn((url: string) => void revoked.push(url));
}

beforeEach(() => {
  vi.useFakeTimers();
  stubObjectUrls();
  clicked = [];
  // Anchors are never attached to the document, so spy on the prototype.
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
    this: HTMLAnchorElement,
  ) {
    clicked.push(this);
  });
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("downloadBlob", () => {
  it("clicks an anchor carrying the object URL and the filename", () => {
    downloadBlob(new Blob(["hi"]), "note.txt");

    expect(clicked).toHaveLength(1);
    expect(clicked[0].download).toBe("note.txt");
    expect(clicked[0].href).toContain(created[0]);
  });

  it("revokes the object URL it created", () => {
    downloadBlob(new Blob(["hi"]), "note.txt");
    expect(revoked).toEqual(created);
  });
});

describe("downloadText / downloadBinary", () => {
  it("writes text as text/plain", async () => {
    downloadText("hello", "a.txt");
    const blob = (URL.createObjectURL as ReturnType<typeof vi.fn>).mock
      .calls[0][0] as Blob;
    expect(blob.type).toBe("text/plain");
    expect(await blob.text()).toBe("hello");
  });

  it("writes binary as application/octet-stream", () => {
    downloadBinary(new Uint8Array([1, 2, 3]), "a.bin");
    const blob = (URL.createObjectURL as ReturnType<typeof vi.fn>).mock
      .calls[0][0] as Blob;
    expect(blob.type).toBe("application/octet-stream");
  });

  it("detaches from a WASM-backed view before blobbing", async () => {
    // The .slice() in downloadBinary is what makes this safe: without
    // it, the Blob would alias WASM linear memory that can be zeroized
    // or grown out from under it before the write lands.
    const backing = new Uint8Array([1, 2, 3, 4]);
    const view = backing.subarray(1, 3);
    downloadBinary(view, "a.bin");

    const blob = (URL.createObjectURL as ReturnType<typeof vi.fn>).mock
      .calls[0][0] as Blob;
    backing.fill(0);

    expect(new Uint8Array(await blob.arrayBuffer())).toEqual(
      new Uint8Array([2, 3]),
    );
  });

  it("downloadResults writes one file per result", () => {
    downloadResults([
      { name: "a.bin", data: new Uint8Array([1]) },
      { name: "b.bin", data: new Uint8Array([2]) },
    ]);
    expect(clicked.map((a) => a.download)).toEqual(["a.bin", "b.bin"]);
  });

  it("downloadResults writes nothing for an empty list", () => {
    downloadResults([]);
    expect(clicked).toHaveLength(0);
  });
});

// ── saveCrxViaPrompt ─────────────────────────────────────────────────

interface DownloadsStub {
  download: ReturnType<typeof vi.fn>;
  search: ReturnType<typeof vi.fn>;
  onChanged: {
    addListener: (fn: (d: unknown) => void) => void;
    removeListener: (fn: (d: unknown) => void) => void;
  };
}

let listeners: ((delta: unknown) => void)[];
/** Deltas to deliver as soon as `waitForDownload` attaches its listener.
 *  Firing on attach rather than after a guessed number of microtasks is
 *  what makes these tests deterministic: the number of awaits before the
 *  listener goes on is an implementation detail. */
let queued: Record<string, unknown>[];

/** Wire up a chrome stub. `searchResult` is what `downloads.search`
 *  reports for an already-settled download; the default (`[]`) leaves the
 *  result to arrive via `onChanged`. */
function stubChrome(opts: {
  contains?: boolean;
  request?: boolean | (() => never);
  downloads?: boolean;
  download?: () => Promise<number>;
  searchResult?: unknown[];
}) {
  listeners = [];
  queued = [];
  const downloads: DownloadsStub = {
    download: vi.fn(opts.download ?? (() => Promise.resolve(1))),
    search: vi.fn((_q: unknown, cb: (items: unknown[]) => void) =>
      cb(opts.searchResult ?? []),
    ),
    onChanged: {
      addListener: (fn) => {
        listeners.push(fn);
        if (queued.length > 0) {
          const deltas = queued;
          queued = [];
          queueMicrotask(() => {
            for (const d of deltas) fn(d);
          });
        }
      },
      removeListener: (fn) => {
        const i = listeners.indexOf(fn);
        if (i >= 0) listeners.splice(i, 1);
      },
    },
  };

  vi.stubGlobal("chrome", {
    permissions: {
      contains: () => Promise.resolve(opts.contains ?? true),
      request: () => {
        const r = opts.request ?? true;
        if (typeof r === "function")
          return Promise.reject(new Error("gesture"));
        return Promise.resolve(r);
      },
    },
    ...(opts.downloads === false ? {} : { downloads }),
  });

  return downloads;
}

/** Queue state changes for delivery once the listener is attached.
 *  Defaults to download id 1, the id `downloads.download` resolves with. */
function emitLater(...deltas: Record<string, unknown>[]) {
  queued.push(...deltas.map((d) => ({ id: 1, ...d })));
}

const CRX = new Uint8Array([0x43, 0x72, 0x32, 0x34]); // "Cr24"

describe("saveCrxViaPrompt permission handling", () => {
  it("returns denied when the permission is refused", async () => {
    stubChrome({ contains: false, request: false });
    await expect(saveCrxViaPrompt(CRX, "a.crx")).resolves.toBe("denied");
  });

  it("returns denied rather than throwing when there is no user gesture", async () => {
    // chrome.permissions.request throws outright when called without a
    // gesture -- e.g. the auto-save right after an async sign. The caller
    // must get a fallback, not an unhandled rejection.
    stubChrome({
      contains: false,
      request: () => {
        throw new Error("gesture");
      },
    });
    await expect(saveCrxViaPrompt(CRX, "a.crx")).resolves.toBe("denied");
  });

  it("skips the request when the permission is already granted", async () => {
    // An already-granted permission needs no gesture, which is what makes
    // auto-save work on every sign after the first.
    const downloads = stubChrome({ contains: true });
    emitLater({ state: { current: "complete" } });
    await expect(saveCrxViaPrompt(CRX, "a.crx")).resolves.toBe("saved");
    expect(downloads.download).toHaveBeenCalled();
  });

  it("returns unsupported when the downloads namespace is absent", async () => {
    // The @types claim it is always there; it only exists once the
    // optional permission is actually granted.
    stubChrome({ downloads: false });
    await expect(saveCrxViaPrompt(CRX, "a.crx")).resolves.toBe("unsupported");
  });
});

describe("saveCrxViaPrompt download outcomes", () => {
  it("requests a Save As download, which is what stops Chrome installing the crx", async () => {
    // saveAs:true => TARGET_DISPOSITION_PROMPT => IsExtensionDownload()
    // early-returns false. Without it, Chrome treats the Cr24 magic as an
    // extension and tries to install it.
    const downloads = stubChrome({});
    emitLater({ state: { current: "complete" } });
    await saveCrxViaPrompt(CRX, "signed.crx");

    expect(downloads.download).toHaveBeenCalledWith(
      expect.objectContaining({ filename: "signed.crx", saveAs: true }),
    );
  });

  it("resolves saved on completion", async () => {
    stubChrome({});
    emitLater({ state: { current: "complete" } });
    await expect(saveCrxViaPrompt(CRX, "a.crx")).resolves.toBe("saved");
  });

  it("ignores state changes for other downloads", async () => {
    stubChrome({});
    emitLater(
      { id: 99, state: { current: "interrupted" } },
      { state: { current: "complete" } },
    );
    await expect(saveCrxViaPrompt(CRX, "a.crx")).resolves.toBe("saved");
  });

  it("maps a rejected download to cancelled when the message says so", async () => {
    // Dismissing the Save As dialog rejects with "canceled".
    stubChrome({
      download: () => Promise.reject(new Error("Download canceled")),
    });
    await expect(saveCrxViaPrompt(CRX, "a.crx")).resolves.toBe("cancelled");
  });

  it("maps any other rejected download to blocked", async () => {
    stubChrome({ download: () => Promise.reject(new Error("Disk full")) });
    await expect(saveCrxViaPrompt(CRX, "a.crx")).resolves.toBe("blocked");
  });

  it.each([
    ["USER_CANCELED", "cancelled"],
    ["USER_SHUTDOWN", "cancelled"],
    ["FILE_BLOCKED", "blocked"],
    ["FILE_NO_SPACE", "blocked"],
    ["FILE_VIRUS_INFECTED", "blocked"],
    [undefined, "blocked"],
  ])("maps an interruption reason of %s to %s", async (reason, expected) => {
    // Only a genuine user cancel is "cancelled"; everything else must
    // surface the drag-out fallback instead of acting like the user
    // changed their mind.
    stubChrome({});
    emitLater({
      state: { current: "interrupted" },
      ...(reason ? { error: { current: reason } } : {}),
    });
    await expect(saveCrxViaPrompt(CRX, "a.crx")).resolves.toBe(expected);
  });

  it("settles from search when the download finished before the listener attached", async () => {
    // The race this closes: a tiny file can reach a terminal state
    // between download() resolving and addListener() running, and no
    // onChanged event ever arrives.
    stubChrome({ searchResult: [{ state: "complete" }] });
    await expect(saveCrxViaPrompt(CRX, "a.crx")).resolves.toBe("saved");
  });

  it("settles from search for an already-interrupted download", async () => {
    stubChrome({
      searchResult: [{ state: "interrupted", error: "FILE_BLOCKED" }],
    });
    await expect(saveCrxViaPrompt(CRX, "a.crx")).resolves.toBe("blocked");
  });

  it("keeps waiting when search reports an in-progress download", async () => {
    stubChrome({ searchResult: [{ state: "in_progress" }] });
    emitLater({ state: { current: "complete" } });
    await expect(saveCrxViaPrompt(CRX, "a.crx")).resolves.toBe("saved");
  });

  it("detaches its listener once settled", async () => {
    stubChrome({});
    emitLater({ state: { current: "complete" } });
    await saveCrxViaPrompt(CRX, "a.crx");
    expect(listeners).toHaveLength(0);
  });

  it("revokes the object URL after the grace period", async () => {
    // Revoking immediately can race Chrome actually reading the blob, so
    // the revoke is deferred a minute rather than run inline.
    stubChrome({});
    emitLater({ state: { current: "complete" } });
    await saveCrxViaPrompt(CRX, "a.crx");

    expect(revoked).toHaveLength(0);
    vi.advanceTimersByTime(60_000);
    expect(revoked).toEqual(created);
  });

  it("revokes the object URL even when the download never starts", async () => {
    stubChrome({ download: () => Promise.reject(new Error("Disk full")) });
    await saveCrxViaPrompt(CRX, "a.crx");
    vi.advanceTimersByTime(60_000);
    expect(revoked).toEqual(created);
  });
});
