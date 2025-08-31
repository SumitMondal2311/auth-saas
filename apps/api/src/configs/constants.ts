import { env } from "./env";

export const constant = {
    IS_PRODUCTION: env.NODE_ENV === "production",
};
