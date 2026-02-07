import type { Meta, StoryObj } from "@storybook/react";

import { Input } from "../input";
import { Label } from "../label";

const meta = {
  title: "Components/Label",
  component: Label,
} satisfies Meta<typeof Label>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: { children: "Label text" },
};

export const WithInput: Story = {
  render: () => (
    <div className="flex flex-col gap-2">
      <Label htmlFor="email">Email</Label>
      <Input id="email" type="email" placeholder="you@example.com" />
    </div>
  ),
};
