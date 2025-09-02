import { prisma } from "@auth-saas/database";
import { hash } from "argon2";
import { randomBytes } from "crypto";
import { env } from "../../configs/env.js";
import { redis } from "../../configs/redis.js";
import { addDurationToNow } from "../../utils/add-duration-to-now.js";
import { AppError } from "../../utils/app-error.js";
import { hmacSHA256 } from "../../utils/hmac-sha256.js";
import { redisKey } from "../../utils/redis-keys.js";

export const signupService = async ({
    ipAddress,
    userAgent,
    email,
    password,
}: {
    ipAddress?: string;
    userAgent?: string;
    email: string;
    password: string;
}): Promise<void> => {
    const emailAddressRecord = await prisma.emailAddress.findUnique({
        where: { email },
        select: {
            isVerified: true,
            id: true,
            userId: true,
        },
    });
    if (emailAddressRecord) {
        if (emailAddressRecord.isVerified) {
            throw new AppError(409, {
                message: "Email already in use",
                details: "This email is already registered and verified.",
            });
        }

        const isRateLimited = await redis.exists(redisKey.signupEmailRateLimit(email));
        if (isRateLimited) {
            throw new AppError(429, {
                message: "Rate limit exceeded",
                details:
                    "Too Many Requests: You can request a new verification email every 60 seconds.",
            });
        }

        const verificationResends = await redis.incr(redisKey.signupEmailResends(email));
        if (verificationResends === 1) {
            await redis.expire(redisKey.signupEmailResends(email), 24 * 60 * 60);
        } else if (verificationResends >= 5) {
            throw new AppError(429, {
                message: "Daily limit reached",
                details:
                    "Too Many Requests: You have reached the daily limit for verification emails.",
            });
        }

        const tokenSecret = randomBytes(32).toString("hex");
        await prisma.$transaction(async (tx) => {
            const { id: emailAddressId, userId } = emailAddressRecord;
            await tx.token.deleteMany({
                where: {
                    emailAddressId,
                    userId,
                    type: "EMAIL_VERIFICATION",
                },
            });
            await tx.token.create({
                data: {
                    hashedSecret: hmacSHA256(tokenSecret),
                    type: "EMAIL_VERIFICATION",
                    expiresAt: addDurationToNow(env.EMAIL_VERIFICATION_TOKEN_EXPIRY * 1000),
                    user: {
                        connect: {
                            id: userId,
                        },
                    },
                    emailAddress: {
                        connect: {
                            id: emailAddressId,
                        },
                    },
                },
            });
        });

        // resend a new verification email
        await redis.set(redisKey.signupEmailRateLimit(email), "1", "EX", 60);
        return;
    }

    const tokenSecret = randomBytes(32).toString("hex");
    await prisma.$transaction(async (tx) => {
        const user = await tx.user.create({
            data: {
                status: "VERIFICATION_PENDING",
            },
        });
        const newEmailAddress = await tx.emailAddress.create({
            data: {
                email,
                user: {
                    connect: {
                        id: user.id,
                    },
                },
            },
        });
        const { id: emailAddressId, userId } = newEmailAddress;
        await tx.account.create({
            data: {
                providerUserId: email,
                hashedPassword: await hash(password),
                user: {
                    connect: {
                        id: userId,
                    },
                },
            },
        });
        await tx.auditLog.create({
            data: {
                event: "ACCOUNT_CREATED",
                ipAddress,
                userAgent,
                user: {
                    connect: {
                        id: userId,
                    },
                },
            },
        });
        await tx.token.create({
            data: {
                hashedSecret: hmacSHA256(tokenSecret),
                type: "EMAIL_VERIFICATION",
                expiresAt: addDurationToNow(env.EMAIL_VERIFICATION_TOKEN_EXPIRY * 1000),
                user: {
                    connect: {
                        id: userId,
                    },
                },
                emailAddress: {
                    connect: {
                        id: emailAddressId,
                    },
                },
            },
        });
        // send a verification email
    });

    return;
};
