import { defineConfig } from "eslint/config";
import turboPlugin from "eslint-plugin-turbo";

import { baseConfig } from "@amibeingpwned/eslint-config/base";
import { reactConfig } from "@amibeingpwned/eslint-config/react";

export default defineConfig(
  {
    ignores: [
      ".wxt/**",
      ".output/**",
      "gpg-wasm/pkg/**",
      "gpg-wasm/target/**",
    ],
  },
  baseConfig,
  reactConfig,
  {
    plugins: { turbo: turboPlugin },
    rules: {
      "turbo/no-undeclared-env-vars": [
        "error",
        { allowList: ["^DEV$", "^PROD$", "^MODE$"] },
      ],
      "react-hooks/set-state-in-effect": "off",
    },
  },
);
