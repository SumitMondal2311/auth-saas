import { env } from "../configs/env.js";
import { Redis } from "ioredis";

export const redis = new Redis(env.REDIS_URL);

redis.on("close", () => console.log("Redis disconnected successfully"));
redis.on("error", (err) => console.error(`Redis error: ${err}`));
redis.on("connect", () => console.log("Redis connected successfully"));
