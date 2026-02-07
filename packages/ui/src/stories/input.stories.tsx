import type { Meta, StoryObj } from "@storybook/react";

import { Input } from "../input";

const meta = {
  title: "Components/Input",
  component: Input,
  argTypes: {
    type: {
      control: "select",
      options: ["text", "email", "password", "number", "search", "tel", "url"],
    },
    disabled: { control: "boolean" },
    placeholder: { control: "text" },
  },
} satisfies Meta<typeof Input>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: { placeholder: "Enter text..." },
};

export const Email: Story = {
  args: { type: "email", placeholder: "you@example.com" },
};

export const Password: Story = {
  args: { type: "password", placeholder: "Password" },
};

export const Disabled: Story = {
  args: { placeholder: "Disabled input", disabled: true },
};

export const WithValue: Story = {
  args: { defaultValue: "Hello world" },
};

export const File: Story = {
  args: { type: "file" },
};
