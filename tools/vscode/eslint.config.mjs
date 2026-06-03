// @ts-check
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["out/**", "node_modules/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      // Node-host globals (Buffer, process, console, etc.).
      globals: { Buffer: "readonly", process: "readonly", console: "readonly" },
    },
  }
);
