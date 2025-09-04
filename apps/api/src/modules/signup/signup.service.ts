import { prisma } from "@auth-saas/database";
import { hash } from "argon2";
import { randomBytes } from "crypto";
import { env } from "../../configs/env.js";
import { redis } from "../../lib/redis.js";
import { addDurationToNow } from "../../utils/add-duration-to-now.js";
import { AppError } from "../../utils/app-error.js";
import { hmacSHA256 } from "../../utils/hmac-sha256.js";
import { redisKey } from "../../utils/redis-keys.js";
import { sendVerificationEmail } from "../../emails/service.js";

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
                details: "Provided email is already registered and verified.",
            });
        }

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
            const { id: emailAddressId, userId } = emailAddressRecord;
            await tx.token.deleteMany({
                where: {
                    emailAddressId,
                    userId,
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
        return;
    }

    const tokenSecret = randomBytes(32).toString("hex");
    await prisma.$transaction(async (tx) => {
        const newUser = await tx.user.create({
            data: {
                status: "VERIFICATION_PENDING",
            },
        });
        const newEmailAddress = await tx.emailAddress.create({
            data: {
                email,
                user: {
                    connect: {
                        id: newUser.id,
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

    return;
};
