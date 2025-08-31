import globals from "globals";
import tseslint from "typescript-eslint";
import { config as baseConfig } from "./base.js";

/** @type {import("eslint").Linter.Config[]} */

export const config = [
    ...baseConfig,
    {
        languageOptions: {
            parser: tseslint.parser,
            parserOptions: {
                project: ["apps/api/tsconfig.json"],
            },
            globals: {
                ...globals.node,
            },
        },
    },
];
