/**
 * @vitest-environment jsdom
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { isFullyVisible, scrollportOf, verticalBounds } from "./scrollport";

/** The scrollport is offset from the viewport (a header sits above it),
 *  so "visible" is measured against the port's own bounds -- comparing
 *  against 0/innerHeight would call a card hidden behind the header
 *  visible and skip the scroll that would reveal it. */
const port = { top: 90, bottom: 500 };

describe("isFullyVisible", () => {
  it("accepts a card inside the port", () => {
    expect(isFullyVisible({ top: 200, bottom: 280 }, port)).toBe(true);
  });

  it("accepts a card flush with either edge", () => {
    expect(isFullyVisible({ top: 90, bottom: 170 }, port)).toBe(true);
    expect(isFullyVisible({ top: 420, bottom: 500 }, port)).toBe(true);
  });

  it("rejects a card below the fold", () => {
    expect(isFullyVisible({ top: 560, bottom: 640 }, port)).toBe(false);
  });

  it("rejects a card scrolled off the top", () => {
    expect(isFullyVisible({ top: -53, bottom: 27 }, port)).toBe(false);
  });

  it("rejects a card only PARTLY in view", () => {
    // The case a naive intersection test gets wrong: the top edge is in
    // the port, so the card is "on screen" -- but its fingerprint line
    // and the details arrow are not, which is what the reveal is for.
    expect(isFullyVisible({ top: 460, bottom: 540 }, port)).toBe(false);
    expect(isFullyVisible({ top: 60, bottom: 140 }, port)).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────
// Finding the port, and measuring against it.
//
// The rule `scrollportOf` encodes is that a scrollport is BOTH a style
// question and a size one. A container with `overflow-y: auto` whose
// content fits is not scrolling anything, and stopping at it makes the
// caller scroll the wrong element -- the card stays put and the panel
// looks frozen. jsdom has no layout engine, so the geometry below is
// declared outright: these tests are about the decision, not the
// measurement.
// ─────────────────────────────────────────────────────────────────────

interface Box {
  overflowY?: string;
  scrollHeight?: number;
  clientHeight?: number;
  rect?: { top: number; bottom: number };
}

/** Build a chain of nested divs, outermost first; returns the innermost. */
function chain(...boxes: Box[]): HTMLElement {
  let parent: HTMLElement = document.body;
  let node = document.body;
  for (const box of boxes) {
    node = document.createElement("div");
    // jsdom computes neither of these, so they are defined outright.
    Object.defineProperty(node, "scrollHeight", {
      value: box.scrollHeight ?? 0,
      configurable: true,
    });
    Object.defineProperty(node, "clientHeight", {
      value: box.clientHeight ?? 0,
      configurable: true,
    });
    node.style.overflowY = box.overflowY ?? "visible";
    if (box.rect) {
      const { top, bottom } = box.rect;
      node.getBoundingClientRect = () =>
        ({ top, bottom, height: bottom - top }) as DOMRect;
    }
    parent.appendChild(node);
    parent = node;
  }
  return node;
}

beforeEach(() => {
  document.body.innerHTML = "";
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("scrollportOf", () => {
  it("returns null when nothing between the element and the root scrolls", () => {
    expect(scrollportOf(chain({}, {}))).toBeNull();
  });

  it.each([["auto"], ["scroll"]])("accepts overflow-y: %s", (overflowY) => {
    const el = chain({ overflowY, scrollHeight: 500, clientHeight: 200 }, {});
    expect(scrollportOf(el)).toBe(el.parentElement);
  });

  it.each([["visible"], ["hidden"], ["clip"]])(
    "rejects overflow-y: %s even when the content overflows",
    (overflowY) => {
      const el = chain({ overflowY, scrollHeight: 500, clientHeight: 200 }, {});
      expect(scrollportOf(el)).toBeNull();
    },
  );

  it("skips a scrollable-styled container whose content fits", () => {
    // The bug this rule prevents: blaming a container that has
    // overflow-y:auto but nothing to scroll, so the card never appears.
    const el = chain(
      { overflowY: "auto", scrollHeight: 200, clientHeight: 200 },
      {},
    );
    expect(scrollportOf(el)).toBeNull();
  });

  it("returns the NEAREST scrolling ancestor, not the outermost", () => {
    const el = chain(
      { overflowY: "auto", scrollHeight: 900, clientHeight: 100 },
      { overflowY: "auto", scrollHeight: 500, clientHeight: 200 },
      {},
    );
    expect(scrollportOf(el)).toBe(el.parentElement);
  });

  it("walks past non-scrolling ancestors to reach a scrolling one", () => {
    const el = chain(
      { overflowY: "auto", scrollHeight: 900, clientHeight: 100 },
      {},
      {},
    );
    expect(scrollportOf(el)).toBe(el.parentElement?.parentElement);
  });
});

describe("verticalBounds", () => {
  it("falls back to the viewport when nothing scrolls", () => {
    vi.stubGlobal("innerHeight", 640);
    const el = chain({}, { rect: { top: 10, bottom: 40 } });

    expect(verticalBounds(el)).toEqual({
      rect: { top: 10, bottom: 40 },
      bounds: { top: 0, bottom: 640 },
    });
  });

  it("measures against the scrollport's own box when one is found", () => {
    // The distinction the header comment above is about: a card can be
    // inside the viewport and still clipped by the panel it lives in.
    const el = chain(
      {
        overflowY: "auto",
        scrollHeight: 900,
        clientHeight: 100,
        rect: { top: 90, bottom: 500 },
      },
      { rect: { top: 460, bottom: 540 } },
    );

    const { rect, bounds } = verticalBounds(el);
    expect(bounds).toEqual({ top: 90, bottom: 500 });
    expect(isFullyVisible(rect, bounds)).toBe(false);
  });
});
