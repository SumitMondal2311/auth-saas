import { prisma } from "@auth-saas/database";
import { setTimeout } from "timers/promises";
import { env } from "./env.js";

export const reconnectDB = async () => {
    for (let attempt = 1; attempt <= env.DATABASE_MAX_RETRIES; attempt++) {
        try {
            await prisma.$connect();
            console.log("Reconnected to database successfully");
            return;
        } catch (_error) {
            const wait = 2 ** attempt * 1000;
            console.warn(`Failed reconnecting to database on attempt ${attempt}`);
            console.warn(`Retrying in ${wait / 1000}s...`);
            await setTimeout(wait);
        }
    }

    console.error("Database connection failed after multiple retries");
    process.exit(1);
};

export const connectDB = async () => {
    try {
        await prisma.$connect();
        console.log("Database connected successfully");
    } catch (_error) {
        console.error("Failed initial database conenction");
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
