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
      // Extends the base config's em-dash-only rule to en-dashes too.
      // User-facing strings use plain hyphens; comments are untouched
      // (they aren't Literal/TemplateElement/JSXText nodes).
      "no-restricted-syntax": [
        "error",
        {
          selector: "Literal[value=/[\\u2013\\u2014]/]",
          message:
            "Em/en dashes are not allowed in string literals. Use a regular hyphen (-) or reword the string.",
        },
        {
          selector: "TemplateElement[value.raw=/[\\u2013\\u2014]/]",
          message:
            "Em/en dashes are not allowed in template literals. Use a regular hyphen (-) or reword the string.",
        },
        {
          selector: "JSXText[value=/[\\u2013\\u2014]/]",
          message:
            "Em/en dashes are not allowed in JSX text. Use a regular hyphen (-) or reword the string.",
        },
      ],
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
