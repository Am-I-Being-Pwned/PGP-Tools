import { expect, test } from "./fixtures";

test("extension loads and boots the side panel into onboarding", async ({
  panel,
}) => {
  // First run with a clean profile lands on onboarding.
  await expect(panel.getByText("PGP Tools")).toBeVisible();
  await expect(
    panel.getByText("Where should we store your data?"),
  ).toBeVisible();
});
