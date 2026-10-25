// Scratch: measure candidate labels in the panel's own font.
import path from "node:path";
import { test } from "@playwright/test";
import { getExtensionId, launchExtensionContext } from "../e2e/fixtures";

const C: Record<string, string[]> = JSON.parse(process.env.CANDS ?? "{}");
test("measure", async () => {
  const ctx = await launchExtensionContext(path.resolve(import.meta.dirname, "..", ".output", "chrome-mv3"));
  const id = await getExtensionId(ctx);
  const p = await ctx.newPage();
  await p.goto(`chrome-extension://${id}/sidepanel.html`);
  await p.waitForTimeout(800);
  const out = await p.evaluate((C) => {
    const fam = getComputedStyle(document.body).fontFamily;
    const c = document.createElement("canvas").getContext("2d")!;
    const res: Record<string, string> = { fam };
    for (const [slot, list] of Object.entries(C)) {
      const [w, px] = slot.split("@");
      c.font = `${w} ${px} ${fam}`;
      res[slot] = list.map((s) => `${s}=${Math.round(c.measureText(s).width)}`).join("  ");
    }
    return res;
  }, C);
  console.log(JSON.stringify(out, null, 1));
  await ctx.close();
});
