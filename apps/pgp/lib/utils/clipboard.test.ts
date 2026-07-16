import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getPreferences } from "../storage/preferences";
import { scheduleClipboardClear } from "./clipboard";

vi.mock("../storage/preferences", () => ({
  getPreferences: vi.fn(),
}));

const mockedGetPreferences = vi.mocked(getPreferences);

/** Minimal prefs stub: the scheduler only reads clipboardWipeSeconds. */
function prefsWith(clipboardWipeSeconds: number) {
  return { clipboardWipeSeconds } as Awaited<ReturnType<typeof getPreferences>>;
}

describe("scheduleClipboardClear", () => {
  const writeText = vi.fn(() => Promise.resolve());

  beforeEach(() => {
    vi.useFakeTimers();
    writeText.mockClear();
    vi.stubGlobal("navigator", { clipboard: { writeText } });
  });

  afterEach(() => {
    // Drain any armed timer so it can't leak into the next test.
    void vi.runAllTimersAsync();
    vi.useRealTimers();
    vi.unstubAllGlobals();
    mockedGetPreferences.mockReset();
  });

  it("wipes after the clipboardWipeSeconds preference", async () => {
    mockedGetPreferences.mockResolvedValue(prefsWith(15));
    scheduleClipboardClear();
    // Let the pref read resolve and arm the timer.
    await vi.advanceTimersByTimeAsync(0);

    await vi.advanceTimersByTimeAsync(14_999);
    expect(writeText).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    expect(writeText).toHaveBeenCalledWith("");
  });

  it("falls back to 60 seconds when preferences are unreadable", async () => {
    mockedGetPreferences.mockRejectedValue(new Error("locked"));
    scheduleClipboardClear();
    await vi.advanceTimersByTimeAsync(0);

    await vi.advanceTimersByTimeAsync(59_999);
    expect(writeText).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    expect(writeText).toHaveBeenCalledWith("");
  });

  it("uses an explicit delay without reading preferences", async () => {
    scheduleClipboardClear(30_000);
    expect(mockedGetPreferences).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(30_000);
    expect(writeText).toHaveBeenCalledWith("");
  });

  it("resets the single deadline on re-copy", async () => {
    scheduleClipboardClear(10_000);
    await vi.advanceTimersByTimeAsync(9_000);
    scheduleClipboardClear(10_000);

    await vi.advanceTimersByTimeAsync(9_999);
    expect(writeText).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    expect(writeText).toHaveBeenCalledTimes(1);
  });
});
