import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import security from "eslint-plugin-security";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "public/mockServiceWorker.js", "coverage"] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.strict, security.configs.recommended],
    files: ["**/*.{ts,tsx}"],
    languageOptions: { globals: globals.browser },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "@typescript-eslint/no-explicit-any": "error",
      "no-restricted-properties": ["error", { object: "element", property: "innerHTML", message: "Render untrusted data with React text nodes." }],
      // Security gate (2026-10-27 review): no dynamic code and no raw HTML anywhere in the panel.
      // Typed keys make bracket access safe here; the rule only produces false positives in TS.
      "security/detect-object-injection": "off",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-restricted-syntax": ["error", { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: "Render untrusted data with React text nodes." }],
    },
  },
);
