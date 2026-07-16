import { describe, expect, it } from "vitest";

import type { WorkspaceAction } from "./messages";
import { COMMAND_TO_MODE, commandToMode } from "./mode-commands";

const ALL_MODES: WorkspaceAction[] = ["encrypt", "decrypt", "sign", "verify"];

describe("commandToMode", () => {
  it("maps each open-* command to its mode", () => {
    expect(commandToMode("open-encrypt")).toBe("encrypt");
    expect(commandToMode("open-decrypt")).toBe("decrypt");
    expect(commandToMode("open-sign")).toBe("sign");
    expect(commandToMode("open-verify")).toBe("verify");
  });

  it("ignores commands it does not own", () => {
    expect(commandToMode("_execute_action")).toBeUndefined();
    expect(commandToMode("open-settings")).toBeUndefined();
    expect(commandToMode("")).toBeUndefined();
  });

  it("covers every workspace mode exactly once", () => {
    const mapped = Object.values(COMMAND_TO_MODE);
    expect(mapped.toSorted()).toEqual(ALL_MODES.toSorted());
  });

  it("uses the stable open-<mode> id scheme", () => {
    for (const [command, mode] of Object.entries(COMMAND_TO_MODE)) {
      expect(command).toBe(`open-${mode}`);
    }
  });
});
