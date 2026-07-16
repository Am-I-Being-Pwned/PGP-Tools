import { beforeEach, describe, expect, it, vi } from "vitest";

import { toast } from "./toast";

const sonner = vi.hoisted(() =>
  Object.assign(
    vi.fn((..._args: unknown[]) => 0),
    {
      success: vi.fn((..._args: unknown[]) => 1),
      info: vi.fn((..._args: unknown[]) => 2),
      warning: vi.fn((..._args: unknown[]) => 3),
      error: vi.fn((..._args: unknown[]) => 4),
      dismiss: vi.fn((..._args: unknown[]) => undefined),
    },
  ),
);

vi.mock("sonner", () => ({ toast: sonner }));

/** Shape of the React element the wrapper builds for assertive toasts. */
interface AlertElement {
  props: { role?: string; children?: string };
}

describe("toast wrapper", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("passes success messages and the stable id through to sonner", () => {
    toast.success("Public key copied", { id: "clipboard-copied" });
    expect(sonner.success).toHaveBeenCalledExactlyOnceWith(
      "Public key copied",
      { id: "clipboard-copied" },
    );
  });

  it("re-firing with the same id targets the same sonner toast (dedup)", () => {
    toast.success("Copied", { id: "clipboard-copied" });
    toast.success("Copied", { id: "clipboard-copied" });
    const ids = sonner.success.mock.calls.map(
      (call) => (call[1] as { id?: string }).id,
    );
    expect(ids).toEqual(["clipboard-copied", "clipboard-copied"]);
  });

  it("wraps error messages in a role=alert element", () => {
    toast.error("Copy failed", { id: "copy-failed", duration: 8000 });
    const [node, options] = sonner.error.mock.calls[0] as [
      AlertElement,
      { id?: string; duration?: number },
    ];
    expect(node.props.role).toBe("alert");
    expect(node.props.children).toBe("Copy failed");
    expect(options).toEqual({ id: "copy-failed", duration: 8000 });
  });

  it("wraps warning messages in a role=alert element", () => {
    toast.warning("Weak crypto");
    const [node] = sonner.warning.mock.calls[0] as [AlertElement];
    expect(node.props.role).toBe("alert");
    expect(node.props.children).toBe("Weak crypto");
  });

  it("leaves info messages as plain strings (polite region suffices)", () => {
    toast.info("2 contacts updated");
    expect(sonner.info).toHaveBeenCalledExactlyOnceWith(
      "2 contacts updated",
      undefined,
    );
  });

  it("routes neutral messages through bare sonner toast()", () => {
    toast.message("Text cleared", { id: "text-cleared" });
    expect(sonner).toHaveBeenCalledExactlyOnceWith("Text cleared", {
      id: "text-cleared",
    });
  });

  it("forwards dismiss", () => {
    toast.dismiss();
    expect(sonner.dismiss).toHaveBeenCalledExactlyOnceWith(undefined);
  });
});
