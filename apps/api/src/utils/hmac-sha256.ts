import { createHmac } from "crypto";
import { env } from "../configs/env.js";

export const hmacSHA256 = (data: Buffer | string): string => {
    return createHmac("sha256", env.HMAC_SHA256_SECRET_KEY).update(data).digest("hex");
};
