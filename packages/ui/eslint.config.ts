import { defineConfig } from "eslint/config";

import { baseConfig } from "@amibeingpwned/eslint-config/base";
import { reactConfig } from "@amibeingpwned/eslint-config/react";

export default defineConfig(
  {
    ignores: ["dist/**", "src/stories/**", ".storybook/**"],
  },
  baseConfig,
  reactConfig,
);
