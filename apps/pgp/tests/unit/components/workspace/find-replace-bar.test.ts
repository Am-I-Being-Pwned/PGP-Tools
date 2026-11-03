// @vitest-environment jsdom
import { act, createElement, useCallback, useState } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it } from "vitest";

import { FindReplaceBar } from "~/components/workspace/FindReplaceBar";

(
  globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

// A runaway loop would never let `act` settle; throwing ends it as a failure.
const RENDER_CAP = 50;
const noop = () => undefined;

let root: ReturnType<typeof createRoot> | null = null;
afterEach(() => {
  act(() => root?.unmount());
  root = null;
});

describe("FindReplaceBar", () => {
  it("settles when the owner passes an inline getter and stores highlights", () => {
    let renders = 0;
    function Owner() {
      if (++renders > RENDER_CAP) throw new Error("render loop");
      const [, setHighlights] = useState<unknown>(null);
      const onHighlight = useCallback(
        (ranges: unknown, current: number) =>
          setHighlights({ ranges, current }),
        [],
      );
      return createElement(FindReplaceBar, {
        initialQuery: "a",
        focusNonce: 1,
        // New identity every render, as WorkspaceInput passes it.
        getText: () => "banana",
        getSelection: () => ({ start: 0, end: 0 }),
        select: noop,
        apply: noop,
        textVersion: 0,
        onHighlight,
        onClose: noop,
      });
    }

    root = createRoot(document.createElement("div"));
    act(() => root?.render(createElement(Owner)));

    expect(renders).toBeLessThan(10);
  });
});
