import turboPlugin from "eslint-plugin-turbo";
import { defineConfig } from "eslint/config";

import { baseConfig } from "@amibeingpwned/eslint-config/base";
import { reactConfig } from "@amibeingpwned/eslint-config/react";

export default defineConfig(
  {
    ignores: [".wxt/**", ".output/**", "gpg-wasm/pkg/**", "gpg-wasm/target/**"],
  },
  baseConfig,
  reactConfig,
  {
    plugins: { turbo: turboPlugin },
    rules: {
      "turbo/no-undeclared-env-vars": [
        "error",
        // HEADED/CI only affect the Playwright e2e run, not the build.
        { allowList: ["^DEV$", "^PROD$", "^MODE$", "^HEADED$", "^CI$"] },
      ],
      "react-hooks/set-state-in-effect": "off",
    },
  },
  {
    // Playwright E2E tests, not React. The fixture pattern names a
    // `use` argument that the React hooks rule mistakes for a hook.
    files: ["e2e/**"],
    rules: {
      "react-hooks/rules-of-hooks": "off",
    },
  },
);
