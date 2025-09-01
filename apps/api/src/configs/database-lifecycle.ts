import { prisma } from "@auth-saas/database";
import { setTimeout } from "timers/promises";
import { env } from "./env.js";

export const reconnectDB = async (attempt = 1) => {
    try {
        await prisma.$connect();
        console.log("Reconnected to database successfully");
    } catch (error) {
        if (attempt <= env.DATABASE_MAX_RETRIES) {
            const wait = 2 ** attempt * 1000;
            console.warn("Failed reconnecting to database");
            console.warn(`Retrying in ${wait / 1000}s...`);
            await setTimeout(wait);
            await reconnectDB(attempt + 1);
        } else {
            console.error("Database reconnection failed: ", error);
            process.exit(1);
        }
    }
};

export const connectDB = async () => {
    try {
        await prisma.$connect();
        console.log("Database connected successfully");
    } catch (_error) {
        console.error("Failed init database conenction");
        await reconnectDB();
    }
};

export const disconnectDB = async () => {
    try {
        await prisma.$disconnect();
        console.log("Databse disconnected successfully");
    } catch (_error) {
        console.error("Failed to disconnect database");
    }
};
