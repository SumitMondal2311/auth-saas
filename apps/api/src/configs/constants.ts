import { env } from "./env.js";

export const IS_PRODUCTION = env.NODE_ENV === "production";
