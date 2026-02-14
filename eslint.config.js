import tseslint from "typescript-eslint";

export default tseslint.config(
    {
        ignores: ["dist/**", "node_modules/**"],
    },
    ...tseslint.configs.recommended,
    {
        rules: {
            // === TypeScript-specific ===
            "@typescript-eslint/no-unused-vars": [
                "error",
                { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
            ],
            "@typescript-eslint/no-explicit-any": "warn",
            "@typescript-eslint/consistent-type-imports": "error",
            "no-empty-function": "error",
            "no-shadow": "off",
            "@typescript-eslint/no-shadow": "error",
            "no-use-before-define": "off",
            "@typescript-eslint/no-use-before-define": [
                "error",
                { functions: false, classes: true, variables: true },
            ],
            "no-unused-expressions": "off",
            "@typescript-eslint/no-unused-expressions": "error",

            // === Correctness ===
            "eqeqeq": ["error", "always"],
            "curly": "error",
            "prefer-const": "error",
            "no-eval": "error",
            "no-implied-eval": "error",
            "guard-for-in": "error",
            "no-self-compare": "error",
            "no-template-curly-in-string": "error",
            "array-callback-return": "error",
            "default-case-last": "error",
            "default-param-last": "error",
            "no-duplicate-imports": "error",

            // === Safety ===
            "no-caller": "error",
            "no-extend-native": "error",
            "no-extra-bind": "error",
            "no-iterator": "error",
            "no-label-var": "error",
            "no-lone-blocks": "error",
            "no-loop-func": "error",
            "no-multi-str": "error",
            "no-new": "error",
            "no-new-func": "error",
            "no-octal-escape": "error",
            "no-proto": "error",
            "no-return-assign": "error",
            "no-script-url": "error",
            "no-sequences": "error",
            "no-useless-call": "error",
            "no-useless-concat": "error",
            "no-useless-constructor": "error",
            "no-useless-return": "error",
            "no-void": "error",
            "no-eq-null": "error",
            "no-implicit-coercion": "off",
            "no-multi-assign": "error",
            "no-unmodified-loop-condition": "error",

            // === Style (non-formatting, not handled by Prettier) ===
            "no-lonely-if": "error",
            "no-unneeded-ternary": "error",
            "no-nested-ternary": "error",
            "one-var": ["error", "never"],
            "prefer-exponentiation-operator": "error",
            "prefer-promise-reject-errors": "error",
            "radix": ["error", "as-needed"],
            "yoda": "error",
            "func-name-matching": "error",
            "no-undef-init": "error",
            "block-scoped-var": "error",

            // === Async ===
            "require-await": "off", // too strict for CLI tool patterns
            "no-return-await": "error",

            // === CLI tool overrides ===
            "no-console": "off", // CLI needs console
            "no-process-exit": "off", // CLI uses process.exit
        },
    },
);
