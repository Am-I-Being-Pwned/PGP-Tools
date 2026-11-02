import { describe, expect, it, vi } from "vitest";

import { AppError } from "~/lib/errors/app-error";
import {
  createActionRunner,
  engineMessage,
  toErrorMapper,
  type ErrorMapper,
} from "./useAsyncAction";

function setup(mapper: ErrorMapper = () => ({ message: "failed" })) {
  const busy = vi.fn();
  const error = vi.fn();
  const inner = createActionRunner({ busy, error });
  const runner = {
    run: (task: () => Promise<void> | void) => inner.run(task, mapper),
    get inFlight() {
      return inner.inFlight;
    },
  };
  return { runner, busy, error };
}

describe("createActionRunner", () => {
  it("clears the error, flags busy, then unflags on success", async () => {
    const { runner, busy, error } = setup();
    const result = await runner.run(() => {
      expect(runner.inFlight).toBe(true);
    });
    expect(result).toBeNull();
    expect(error.mock.calls).toEqual([[null]]);
    expect(busy.mock.calls).toEqual([[true], [false]]);
    expect(runner.inFlight).toBe(false);
  });

  it("refuses a second run while one is in flight", async () => {
    const { runner } = setup();
    let release!: () => void;
    const second = vi.fn();
    const first = runner.run(
      () => new Promise<void>((resolve) => (release = resolve)),
    );
    await runner.run(second);
    expect(second).not.toHaveBeenCalled();
    release();
    await first;
    await runner.run(second);
    expect(second).toHaveBeenCalledOnce();
  });

  it("maps a throw through the mapper and stores it", async () => {
    const { runner, error, busy } = setup((e) => ({
      message: `mapped ${e instanceof Error ? e.message : ""}`,
    }));
    const result = await runner.run(() => Promise.reject(new Error("boom")));
    expect(result).toEqual({ message: "mapped boom" });
    expect(error).toHaveBeenLastCalledWith({ message: "mapped boom" });
    expect(busy).toHaveBeenLastCalledWith(false);
    expect(runner.inFlight).toBe(false);
  });

  it("shows nothing when the mapper says it was not an error", async () => {
    const { runner, error } = setup(() => null);
    const result = await runner.run(() => Promise.reject(new Error("x")));
    expect(result).toBeNull();
    expect(error).toHaveBeenLastCalledWith(null);
  });
});

describe("error policies", () => {
  it("a fallback string keeps unknown engine text out of the message", () => {
    const presented = toErrorMapper("Generation failed.")(
      new Error("rnp_op_generate: internal state 0x7"),
    );
    expect(presented?.message).toBe("Generation failed.");
    expect(presented?.detail).toContain("rnp_op_generate");
  });

  it("a fallback string still curates known causes", () => {
    const presented = toErrorMapper("x")(
      new AppError("key-locked", "Key is locked"),
    );
    expect(presented?.message).not.toBe("x");
  });

  it("engineMessage surfaces the engine's own text, wasm strings included", () => {
    expect(engineMessage("fallback")("Incorrect passphrase")).toEqual({
      message: "Incorrect passphrase",
    });
    expect(engineMessage("fallback")(42)).toEqual({ message: "fallback" });
  });
});
