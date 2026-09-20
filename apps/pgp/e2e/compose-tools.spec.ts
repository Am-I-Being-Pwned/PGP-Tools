import type { Page } from "@playwright/test";

import { aiCalls, stubBuiltInAi } from "./ai-stub";
import { expect, test } from "./fixtures";
import { onboardWithPassword } from "./helpers";

const PASSWORD = "correct horse battery staple";

// The message box's editing tools: inline formatting, find & replace,
// and translate-before-sending. All three edit the SAME uncontrolled
// textarea the workspace owns, so what these pin is that an edit made
// by a tool lands exactly where a keystroke would (value, selection,
// change handler) -- the tool must not desync the box from the state
// that encrypts it.

const box = (panel: Page) => panel.getByLabel("Message input");

/** Select `needle` inside the box by offsets, as a mouse drag would. */
async function selectText(panel: Page, needle: string): Promise<void> {
  await box(panel).evaluate((el, n) => {
    const ta = el as HTMLTextAreaElement;
    const at = ta.value.indexOf(n);
    ta.focus();
    ta.setSelectionRange(at, at + n.length);
  }, needle);
}

async function selectedText(panel: Page): Promise<string> {
  return box(panel).evaluate((el) => {
    const ta = el as HTMLTextAreaElement;
    return ta.value.slice(ta.selectionStart, ta.selectionEnd);
  });
}

test("formatting swaps the selection for Unicode letter forms, from the toolbar and the keyboard", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await panel.getByRole("tab", { name: "Main" }).click();
  await box(panel).fill("make this bold and this italic");

  await test.step("toolbar: bold", async () => {
    await selectText(panel, "this bold");
    await panel.getByRole("button", { name: "Bold" }).click();
    await expect(box(panel)).toHaveValue("make 𝘁𝗵𝗶𝘀 𝗯𝗼𝗹𝗱 and this italic");
    // The words stay selected so a second press takes the style off.
    expect(await selectedText(panel)).toBe("𝘁𝗵𝗶𝘀 𝗯𝗼𝗹𝗱");
  });

  await test.step("a second press takes it off", async () => {
    await panel.getByRole("button", { name: "Bold" }).click();
    await expect(box(panel)).toHaveValue("make this bold and this italic");
  });

  await test.step("keyboard: italic", async () => {
    await selectText(panel, "this italic");
    await box(panel).press("ControlOrMeta+i");
    await expect(box(panel)).toHaveValue("make this bold and 𝘵𝘩𝘪𝘴 𝘪𝘵𝘢𝘭𝘪𝘤");
  });

  await test.step("Cmd/Ctrl+Z undoes the tool edit like typing, and Shift+Z redoes it", async () => {
    // The tools write through the native editing path, so the browser's
    // own undo stack owns them -- no bespoke history to get out of sync
    // with what the user typed in between.
    await box(panel).press("ControlOrMeta+z");
    await expect(box(panel)).toHaveValue("make this bold and this italic");
    await box(panel).press("ControlOrMeta+Shift+z");
    await expect(box(panel)).toHaveValue("make this bold and 𝘵𝘩𝘪𝘴 𝘪𝘵𝘢𝘭𝘪𝘤");
    await box(panel).press("ControlOrMeta+z");
  });

  await test.step("the tools are not offered on pasted armor (decrypt mode)", async () => {
    await panel.getByRole("combobox").first().click();
    await panel.getByRole("option", { name: "Decrypt" }).click();
    await expect(panel.getByRole("button", { name: "Bold" })).toHaveCount(0);
  });
});

test("find & replace steps through matches and replaces one or all", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await panel.getByRole("tab", { name: "Main" }).click();
  await box(panel).fill("the cat sat on the mat with the Cat");

  // Opened with a selection, the field starts from it.
  await selectText(panel, "cat");
  await box(panel).press("ControlOrMeta+f");
  const bar = panel.getByRole("search", { name: "Find and replace" });
  await expect(bar).toBeVisible();
  const find = bar.getByRole("textbox", { name: "Find", exact: true });
  await expect(find).toBeFocused();
  await expect(find).toHaveValue("cat");

  await test.step("the query selects the first match and counts them", async () => {
    await expect(bar.getByText("1/2")).toBeVisible();
    expect(await selectedText(panel)).toBe("cat");
  });

  await test.step("Enter steps forward and wraps; the count follows", async () => {
    await find.press("Enter");
    await expect(bar.getByText("2/2")).toBeVisible();
    expect(await selectedText(panel)).toBe("Cat");
    await find.press("Enter");
    await expect(bar.getByText("1/2")).toBeVisible();
  });

  await test.step("match case narrows it", async () => {
    await bar.getByRole("button", { name: "Match case" }).click();
    await expect(bar.getByText("1/1")).toBeVisible();
    await bar.getByRole("button", { name: "Match case" }).click();
  });

  await test.step("replace is behind a chevron; open it, replace one, then all", async () => {
    await expect(bar.getByLabel("Replace with")).toHaveCount(0);
    await bar.getByRole("button", { name: "Show replace" }).click();
    await bar.getByLabel("Replace with").fill("dog");
    await bar.getByRole("button", { name: "Replace", exact: true }).click();
    await expect(box(panel)).toHaveValue("the dog sat on the mat with the Cat");
    await find.fill("the");
    await bar.getByRole("button", { name: "Replace all" }).click();
    // "the dog" -> "dog dog": every "the" goes, the earlier "dog" stays.
    await expect(box(panel)).toHaveValue("dog dog sat on dog mat with dog Cat");
    await expect(bar.getByText("0", { exact: true })).toBeVisible();
  });

  await test.step("Tab goes Find -> Replace, and mod+Enter replaces all", async () => {
    await find.fill("dog");
    await find.press("Tab");
    const replace = bar.getByLabel("Replace with");
    await expect(replace).toBeFocused();
    await replace.fill("cat");
    // Tab from Replace lands on the replace-row buttons, not the icons.
    await replace.press("Tab");
    await expect(
      bar.getByRole("button", { name: "Replace", exact: true }),
    ).toBeFocused();
    await replace.focus();
    // The workspace's run shortcut is the same combo; the bar owns it
    // while focus is inside, so this must replace, not Encrypt.
    await replace.press("ControlOrMeta+Enter");
    await expect(box(panel)).toHaveValue("cat cat sat on cat mat with cat Cat");
    await expect(bar).toBeVisible();
  });

  await test.step("Escape closes the bar and returns focus to the message", async () => {
    await find.press("Escape");
    await expect(bar).toHaveCount(0);
    await expect(box(panel)).toBeFocused();
    // The workspace's own double-Escape clear must not have fired.
    await expect(box(panel)).toHaveValue("cat cat sat on cat mat with cat Cat");
  });
});

test("translate-before-sending replaces the message off one click, with undo", async ({
  context,
  panel,
}) => {
  await stubBuiltInAi(context, { availability: "available", detected: "fr" });
  await panel.reload();
  await onboardWithPassword(panel, PASSWORD);
  await panel.getByRole("tab", { name: "Main" }).click();
  const original = "bonjour tout le monde, comment allez-vous aujourd hui";
  await box(panel).fill(original);

  await test.step("nothing reads the message before the click", async () => {
    const calls = await aiCalls(panel);
    expect(
      calls.filter((c) => !c.startsWith("translator.availability")),
    ).toEqual([]);
  });

  // Before any pick the chip is just "Translate": no language it was
  // never asked for. The menu is a searchable list.
  await panel.getByRole("button", { name: "Translate", exact: true }).click();
  await panel.getByPlaceholder("Search languages").fill("spa");
  await expect(panel.getByRole("option")).toHaveCount(1);
  await panel.getByRole("option", { name: "Spanish" }).click();

  await expect(box(panel)).toHaveValue(`TRANSLATED(${original})`);
  await expect(
    panel.getByText("Translated from English to Spanish"),
  ).toBeVisible();

  await test.step("the source is the user's language: no detector ran, and the session is destroyed", async () => {
    const calls = await aiCalls(panel);
    expect(calls.filter((c) => c.startsWith("detector."))).toEqual([]);
    expect(calls).toContain("translator.create:en");
    expect(calls).toContain("translator.destroy");
  });

  await test.step("the toast's Undo puts the original back; native undo/redo still work", async () => {
    await panel.getByRole("button", { name: "Undo" }).click();
    await expect(box(panel)).toHaveValue(original);
    // The translation and the toast's undo were both native edits, so
    // the browser's own history walks them: Cmd/Ctrl+Z reverts the undo
    // (back to the translation), Shift+Z redoes it.
    await box(panel).press("ControlOrMeta+z");
    await expect(box(panel)).toHaveValue(`TRANSLATED(${original})`);
    await box(panel).press("ControlOrMeta+Shift+z");
    await expect(box(panel)).toHaveValue(original);
  });

  await test.step("the picked language sticks for the next translation", async () => {
    await expect(
      panel.getByRole("button", { name: "Translate to Spanish" }),
    ).toBeVisible();
  });

  await test.step("the command palette: Translate message... then pick a language", async () => {
    await box(panel).press("ControlOrMeta+k");
    const palette = panel.getByRole("dialog", { name: "Command palette" });
    await palette.getByPlaceholder("Type a command...").fill("transl");
    await palette.getByText("Translate message...").click();
    // Second step: a searchable language list, last pick first.
    const pick = palette.getByPlaceholder("Pick a language...");
    await expect(pick).toBeFocused();
    await expect(palette.getByRole("option").first()).toHaveText(
      "Spanish (last used)",
    );
    await pick.fill("germ");
    await palette.getByRole("option", { name: "German" }).click();
    await expect(box(panel)).toHaveValue(`TRANSLATED(${original})`);
    await expect(
      panel.getByText("Translated from English to German"),
    ).toBeVisible();
  });
});

test("the command palette lists the formatting tools and runs them on the selection", async ({
  panel,
}) => {
  await onboardWithPassword(panel, PASSWORD);
  await panel.getByRole("tab", { name: "Main" }).click();
  await box(panel).fill("make this bold");
  await selectText(panel, "this bold");

  await box(panel).press("ControlOrMeta+k");
  const palette = panel.getByRole("dialog", { name: "Command palette" });
  await palette.getByPlaceholder("Type a command...").fill("bold");
  await palette.getByText("Bold selection").click();
  await expect(box(panel)).toHaveValue("make 𝘁𝗵𝗶𝘀 𝗯𝗼𝗹𝗱");

  await test.step("absent where there is no message to edit", async () => {
    await panel.getByRole("tab", { name: "Keys" }).click();
    await panel.keyboard.press("ControlOrMeta+k");
    await palette.getByPlaceholder("Type a command...").fill("find");
    await expect(palette.getByText("Find and replace in message")).toHaveCount(
      0,
    );
    await expect(palette.getByText("Translate message...")).toHaveCount(0);
  });
});
