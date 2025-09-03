import { prisma } from "@auth-saas/database";
import { verify } from "argon2";
import { randomBytes, randomUUID } from "crypto";
import { setTimeout } from "timers/promises";
import { env } from "../../configs/env.js";
import { signToken } from "../../lib/jwt.js";
import { redis } from "../../lib/redis.js";
import { addDurationToNow } from "../../utils/add-duration-to-now.js";
import { AppError } from "../../utils/app-error.js";
import { hmacSHA256 } from "../../utils/hmac-sha256.js";
import { redisKey } from "../../utils/redis-keys.js";

export const loginService = async ({
    ipAddress,
    userAgent,
    email,
    password,
}: {
    ipAddress?: string;
    userAgent?: string;
    email: string;
    password: string;
}): Promise<{
    refreshToken: string;
    userId: string;
    sessionId: string;
}> => {
    const emailAddressRecord = await prisma.emailAddress.findUnique({
        where: {
            email,
        },
        select: {
            isVerified: true,
            id: true,
            userId: true,
        },
    });

    if (!emailAddressRecord) {
        throw new AppError(404, {
            message: "Email not found",
            details: "No account exists with the provided email address.",
        });
    }

    const { id: emailAddressId, userId } = emailAddressRecord;

    if (!emailAddressRecord.isVerified) {
        const isRateLimited = await redis.exists(redisKey.loginEmailRateLimit(email));
        if (isRateLimited) {
            throw new AppError(429, {
                message: "Rate limit exceeded",
                details:
                    "Too Many Requests: You can request a new verification email every 60 seconds.",
            });
        }

        const verificationResends = await redis.incr(redisKey.loginEmailResends(email));
        if (verificationResends === 1) {
            await redis.expire(redisKey.loginEmailResends(email), 24 * 60 * 60);
        } else if (verificationResends >= 5) {
            throw new AppError(429, {
                message: "Daily limit reached",
                details:
                    "Too Many Requests: You have reached the daily limit for verification emails.",
            });
        }

        const tokenSecret = randomBytes(32).toString("hex");
        await prisma.$transaction(async (tx) => {
            await tx.token.deleteMany({
                where: {
                    userId: userId,
                    type: "EMAIL_VERIFICATION",
                },
            });
            return await tx.token.create({
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
        await redis.set(redisKey.loginEmailRateLimit(email), "1", "EX", 60);

        throw new AppError(202, {
            message: "Verification email has been resent",
            details: "Email is not verified.",
        });
    }

    const account = await prisma.account.findUnique({
        where: {
            providerUserId_provider: {
                provider: "LOCAL",
                providerUserId: email,
            },
        },
        select: {
            hashedPassword: true,
        },
    });

    if (!account) {
        throw new AppError(404, {
            message: "Account not found",
            details: "No account is linked to this email address.",
        });
    }

    const passwordMatched = await verify(account.hashedPassword || "", password);
    if (!passwordMatched) {
        await setTimeout(1000);
        throw new AppError(401, {
            message: "Invalid credentials",
            details: "The provided password is incorrect.",
        });
    }

    const sessionRecords = await prisma.session.findMany({
        where: {
            userId,
        },
        orderBy: {
            updatedAt: "asc",
        },
        select: {
            id: true,
        },
    });

    const refreshTokenId = randomUUID();
    const sessionId = randomUUID();
    const refreshToken = await signToken(
        {
            jti: refreshTokenId,
            typ: "refresh",
            sub: userId,
            sid: sessionId,
        },
        addDurationToNow(env.REFRESH_TOKEN_EXPIRY * 1000)
    );

    await prisma.$transaction(async (tx) => {
        if (sessionRecords.length >= env.SESSION_LIMIT) {
            await tx.session.update({
                where: {
                    id: sessionRecords[0].id,
                },
                data: {
                    isRevoked: true,
                },
            });
        }
        await tx.session.create({
            data: {
                id: sessionId,
                expiresAt: addDurationToNow(env.REFRESH_TOKEN_EXPIRY * 1000),
                ipAddress,
                userAgent,
                refreshTokenId,
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
        await tx.auditLog.create({
            data: {
                event: "LOGGED_IN",
                ipAddress,
                userAgent,
                user: {
                    connect: {
                        id: userId,
                    },
                },
            },
        });
    });

    return {
        refreshToken,
        userId,
        sessionId,
    };
};
