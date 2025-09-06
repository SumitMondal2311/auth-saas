import { prisma } from "@auth-saas/database";
import { verify } from "argon2";
import { randomBytes, randomUUID } from "crypto";
import { setTimeout } from "timers/promises";
import { env } from "../../configs/env.js";
import { sendVerificationEmail } from "../../emails/service.js";
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
            details: "No account found in the database associated with the provided email address.",
        });
    }

    const { id: emailAddressId, userId } = emailAddressRecord;

    if (!emailAddressRecord.isVerified) {
        const isRateLimited = await redis.exists(redisKey.authEmailRateLimit(email));
        if (isRateLimited) {
            throw new AppError(429, {
                message: "Please wait before requesting another email",
                details: "Attempted to send two consecutive emails within a minute.",
            });
        }

        const verificationResends = await redis.incr(redisKey.authEmailResends(email));
        if (verificationResends === 1) {
            await redis.expire(redisKey.authEmailResends(email), 24 * 60 * 60);
        } else if (verificationResends >= 5) {
            throw new AppError(429, {
                message: "You've reached today's limit for verification",
                details: "Daily limit for verification has been reached for this email address.",
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
            const token = await tx.token.create({
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
            await sendVerificationEmail(email, `${token.id}.${tokenSecret}`);
        });

        await redis.set(redisKey.authEmailRateLimit(email), "1", "EX", 60);

        throw new AppError(202, {
            message:
                "A verification link has been sent to your email, please check your inbox and verify your email",
            details: "Provided email address is not yet verified.",
        });
    }

    const accountRecord = await prisma.account.findUnique({
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

    if (!accountRecord) {
        throw new AppError(404, {
            message: "Account not found",
            details:
                "No local account exists associated with this email address as providerUserId.",
        });
    }

    const { hashedPassword } = accountRecord;
    if (!hashedPassword) {
        throw new AppError(422, {
            message: "Detected data inconsistency",
            details: "Hashed-Password is stored as NULL in the account record.",
        });
    }

    const passwordMatched = await verify(hashedPassword, password);
    if (!passwordMatched) {
        await setTimeout(1000);
        throw new AppError(401, {
            message: "Invalid credentials",
            details: "Provided password is incorrect.",
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
