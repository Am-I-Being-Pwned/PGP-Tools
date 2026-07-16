import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const toastMock = vi.hoisted(() => ({
  success: vi.fn(),
  info: vi.fn(),
  warning: vi.fn(),
  error: vi.fn(),
}));

const prefsMock = vi.hoisted(() => ({
  getPreferences: vi.fn(),
}));

vi.mock("../lib/toast", () => ({ toast: toastMock }));
vi.mock("../lib/storage/preferences", () => prefsMock);

import { copyToClipboard } from "./useCopyToClipboard";

const writeText = vi.fn<(text: string) => Promise<void>>();

describe("copyToClipboard", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    writeText.mockResolvedValue(undefined);
    prefsMock.getPreferences.mockResolvedValue({ clipboardWipeSeconds: 30 });
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("writes the text and shows a label-based deduped success toast", async () => {
    await expect(copyToClipboard("KEY", { label: "Public key" })).resolves.toBe(
      true,
    );
    expect(writeText).toHaveBeenCalledExactlyOnceWith("KEY");
    expect(toastMock.success).toHaveBeenCalledExactlyOnceWith(
      "Public key copied",
      { id: "clipboard-copy" },
    );
  });

  it("stays silent on success without a label (caller owns feedback)", async () => {
    await expect(copyToClipboard("KEY")).resolves.toBe(true);
    expect(toastMock.success).not.toHaveBeenCalled();
    expect(toastMock.error).not.toHaveBeenCalled();
  });

  it("sensitive copies arm the wipe with the preference delay", async () => {
    await copyToClipboard("SECRET", { sensitive: true });
    writeText.mockClear();

    vi.advanceTimersByTime(29_999);
    expect(writeText).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(writeText).toHaveBeenCalledExactlyOnceWith("");
  });

  it("sensitive copies announce the actual countdown in the toast", async () => {
    await copyToClipboard("SECRET", {
      sensitive: true,
      label: "Revocation certificate",
    });
    expect(toastMock.success).toHaveBeenCalledExactlyOnceWith(
      "Revocation certificate copied - clipboard clears in 30s",
      { id: "clipboard-copy" },
    );
  });

  it("wipeDelayMs overrides the preference", async () => {
    await copyToClipboard("SECRET", { sensitive: true, wipeDelayMs: 10_000 });
    writeText.mockClear();

    vi.advanceTimersByTime(10_000);
    expect(writeText).toHaveBeenCalledExactlyOnceWith("");
    expect(prefsMock.getPreferences).not.toHaveBeenCalled();
  });

  it("non-sensitive copies never arm a wipe", async () => {
    await copyToClipboard("PLAIN");
    writeText.mockClear();
    vi.advanceTimersByTime(600_000);
    expect(writeText).not.toHaveBeenCalled();
  });

  it("surfaces a rejected write as an error toast and returns false", async () => {
    writeText.mockRejectedValueOnce(new Error("Document is not focused."));
    await expect(copyToClipboard("KEY", { label: "Public key" })).resolves.toBe(
      false,
    );
    expect(toastMock.error).toHaveBeenCalledExactlyOnceWith(
      "Copy failed - click the extension panel first, then try again.",
      { id: "clipboard-copy" },
    );
    expect(toastMock.success).not.toHaveBeenCalled();
  });
});
