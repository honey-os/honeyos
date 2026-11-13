import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Linting was switched on for the first time with the Node 26 upgrade
  // (`next lint` is gone in Next 16 and there was no config before it). These
  // two React Compiler rules flag seven existing effects. They stay visible as
  // warnings until each one is rewritten and checked in a browser, rather
  // than being refactored blind inside a dependency upgrade.
  {
    rules: {
      "react-hooks/set-state-in-effect": "warn",
      "react-hooks/immutability": "warn",
    },
  },
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
  ]),
]);

export default eslintConfig;
