import { config as nodeConfig } from "./packages/eslint-config/node.js";

/** @type {import("eslint").Linter.Config[]} */

export default [
    ...nodeConfig.map((cfg) => ({
        ...cfg,
        files: ["apps/api/**/*.{ts,tsx}"],
    })),
    {
        ignores: ["**/node_modules", "**/.turbo", "**/dist"],
    },
];
