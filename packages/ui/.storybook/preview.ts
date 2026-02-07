import type { Preview } from "@storybook/react";

import "./storybook.css";

const preview: Preview = {
  parameters: {
    backgrounds: { disable: true },
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/i,
      },
    },
  },
  decorators: [
    (Story) => {
      document.documentElement.classList.add("dark");
      return Story();
    },
  ],
};

export default preview;
