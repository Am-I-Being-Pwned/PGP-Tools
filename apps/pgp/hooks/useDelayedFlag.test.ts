import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createDelayedFlag } from "./useDelayedFlag";

describe("createDelayedFlag", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("never reports true for an operation faster than the delay", () => {
    const onChange = vi.fn();
    const flag = createDelayedFlag(150, onChange);

    flag.update(true);
    vi.advanceTimersByTime(149);
    flag.update(false);
    vi.advanceTimersByTime(1000);

    expect(onChange).not.toHaveBeenCalledWith(true);
  });

  it("reports true once active has held for the full delay", () => {
    const onChange = vi.fn();
    const flag = createDelayedFlag(150, onChange);

    flag.update(true);
    vi.advanceTimersByTime(149);
    expect(onChange).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(onChange).toHaveBeenCalledExactlyOnceWith(true);
  });

  it("repeated update(true) calls do not restart the delay", () => {
    const onChange = vi.fn();
    const flag = createDelayedFlag(150, onChange);

    flag.update(true);
    vi.advanceTimersByTime(100);
    flag.update(true);
    vi.advanceTimersByTime(50);

    expect(onChange).toHaveBeenCalledExactlyOnceWith(true);
  });

  it("reports false immediately on deactivation and rearms cleanly", () => {
    const onChange = vi.fn();
    const flag = createDelayedFlag(150, onChange);

    flag.update(true);
    vi.advanceTimersByTime(150);
    expect(onChange).toHaveBeenLastCalledWith(true);

    flag.update(false);
    expect(onChange).toHaveBeenLastCalledWith(false);

    // A fresh activation needs the full delay again.
    flag.update(true);
    vi.advanceTimersByTime(149);
    expect(onChange).toHaveBeenLastCalledWith(false);
    vi.advanceTimersByTime(1);
    expect(onChange).toHaveBeenLastCalledWith(true);
  });

  it("does not fire after dispose", () => {
    const onChange = vi.fn();
    const flag = createDelayedFlag(150, onChange);

    flag.update(true);
    flag.dispose();
    vi.advanceTimersByTime(1000);

    expect(onChange).not.toHaveBeenCalled();
  });

  it("deactivating before the delay reports nothing (still false)", () => {
    const onChange = vi.fn();
    const flag = createDelayedFlag(150, onChange);

    flag.update(true);
    flag.update(false);
    vi.advanceTimersByTime(1000);

    expect(onChange).not.toHaveBeenCalled();
  });
});
