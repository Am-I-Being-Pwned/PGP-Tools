import { beforeEach, describe, expect, it, vi } from "vitest";

import { enterNeverCacheMode } from "./never-cache";

const mocks = vi.hoisted(() => ({
  savePreferences: vi.fn<(patch: Record<string, unknown>) => Promise<void>>(),
  clearHistory: vi.fn<() => Promise<void>>(),
  order: [] as string[],
}));

vi.mock("./storage/preferences", () => ({
  savePreferences: (patch: Record<string, unknown>) => {
    mocks.order.push("save");
    return mocks.savePreferences(patch);
  },
}));

vi.mock("./storage/history", () => ({
  clearHistory: () => {
    mocks.order.push("clear");
    return mocks.clearHistory();
  },
}));

describe("enterNeverCacheMode", () => {
  beforeEach(() => {
    mocks.savePreferences.mockReset().mockResolvedValue(undefined);
    mocks.clearHistory.mockReset().mockResolvedValue(undefined);
    mocks.order = [];
  });

  it("turns never-cache on and history capture off in one save", async () => {
    await enterNeverCacheMode();
    expect(mocks.savePreferences).toHaveBeenCalledTimes(1);
    expect(mocks.savePreferences).toHaveBeenCalledWith({
      neverCacheKeys: true,
      historyEnabled: false,
    });
  });

  it("always wipes stored history, even when capture was already off", async () => {
    await enterNeverCacheMode();
    expect(mocks.clearHistory).toHaveBeenCalledTimes(1);
  });

  it("persists the preference flip before wiping history", async () => {
    await enterNeverCacheMode();
    expect(mocks.order).toEqual(["save", "clear"]);
  });

  it("propagates a failed history wipe to the caller", async () => {
    mocks.clearHistory.mockRejectedValueOnce(new Error("boom"));
    await expect(enterNeverCacheMode()).rejects.toThrow("boom");
  });
});
