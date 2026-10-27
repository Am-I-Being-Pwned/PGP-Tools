import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { copyToClipboard } from "./useCopyToClipboard";

const toastMock = vi.hoisted(() => ({
  success: vi.fn(),
  info: vi.fn(),
  warning: vi.fn(),
  error: vi.fn(),
}));

vi.mock("../lib/toast", () => ({ toast: toastMock }));

const writeText = vi.fn<(text: string) => Promise<void>>();

describe("copyToClipboard", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    writeText.mockResolvedValue(undefined);
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

  it("sensitive copies say the secret stays on the clipboard and in its history", async () => {
    await copyToClipboard("SECRET", {
      sensitive: true,
      label: "Revocation certificate",
    });
    expect(toastMock.success).toHaveBeenCalledExactlyOnceWith(
      "Revocation certificate copied",
      {
        id: "clipboard-copy",
        description:
          "It stays on your clipboard, and in any clipboard history, until you copy something else.",
      },
    );
  });

  it("never wipes the clipboard behind the user's back", async () => {
    // A timed wipe could not reach clipboard history and usually failed
    // anyway (T-CLIPBOARD-EXFIL); the copy is the user's to manage.
    await copyToClipboard("SECRET", { sensitive: true });
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
