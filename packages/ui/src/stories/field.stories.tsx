import type { Meta, StoryObj } from "@storybook/react";

import {
  Field,
  FieldContent,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  FieldSeparator,
  FieldSet,
} from "../field";
import { Input } from "../input";

const meta = {
  title: "Components/Field",
  component: Field,
  argTypes: {
    orientation: {
      control: "select",
      options: ["vertical", "horizontal", "responsive"],
    },
  },
} satisfies Meta<typeof Field>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Vertical: Story = {
  render: () => (
    <Field orientation="vertical" className="max-w-sm">
      <FieldLabel>Email</FieldLabel>
      <FieldContent>
        <Input type="email" placeholder="you@example.com" />
        <FieldDescription>We'll never share your email.</FieldDescription>
      </FieldContent>
    </Field>
  ),
};

export const Horizontal: Story = {
  render: () => (
    <Field orientation="horizontal" className="max-w-md">
      <FieldLabel>Username</FieldLabel>
      <FieldContent>
        <Input placeholder="johndoe" />
      </FieldContent>
    </Field>
  ),
};

export const WithError: Story = {
  render: () => (
    <Field orientation="vertical" data-invalid="true" className="max-w-sm">
      <FieldLabel>Password</FieldLabel>
      <FieldContent>
        <Input type="password" aria-invalid />
        <FieldError>Password must be at least 8 characters.</FieldError>
      </FieldContent>
    </Field>
  ),
};

export const WithMultipleErrors: Story = {
  render: () => (
    <Field orientation="vertical" data-invalid="true" className="max-w-sm">
      <FieldLabel>Password</FieldLabel>
      <FieldContent>
        <Input type="password" aria-invalid />
        <FieldError
          errors={[
            { message: "Must be at least 8 characters" },
            { message: "Must contain a number" },
          ]}
        />
      </FieldContent>
    </Field>
  ),
};

export const FieldGroupExample: Story = {
  name: "Field Group",
  render: () => (
    <FieldSet className="max-w-sm">
      <FieldGroup>
        <Field>
          <FieldLabel>First Name</FieldLabel>
          <FieldContent>
            <Input placeholder="John" />
          </FieldContent>
        </Field>
        <FieldSeparator />
        <Field>
          <FieldLabel>Last Name</FieldLabel>
          <FieldContent>
            <Input placeholder="Doe" />
          </FieldContent>
        </Field>
      </FieldGroup>
    </FieldSet>
  ),
};
