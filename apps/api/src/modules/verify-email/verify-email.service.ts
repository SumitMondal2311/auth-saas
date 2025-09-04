import { prisma } from "@auth-saas/database";
import { randomUUID } from "crypto";
import { env } from "../../configs/env.js";
import { signToken } from "../../lib/jwt.js";
import { addDurationToNow } from "../../utils/add-duration-to-now.js";
import { AppError } from "../../utils/app-error.js";
import { constantTimeCompare } from "../../utils/constant-time-compare.js";
import { hmacSHA256 } from "../../utils/hmac-sha256.js";

export const verifyEmailService = async ({
    ipAddress,
    userAgent,
    secret,
    tokenId,
}: {
    ipAddress?: string;
    userAgent?: string;
    secret: string;
    tokenId: string;
}): Promise<{
    refreshToken: string;
    userId: string;
    sessionId: string;
}> => {
    const tokenRecord = await prisma.token.findFirst({
        where: {
            type: "EMAIL_VERIFICATION",
            id: tokenId,
        },
        select: {
            emailAddressId: true,
            expiresAt: true,
            userId: true,
            hashedSecret: true,
        },
    });

    if (!tokenRecord) {
        throw new AppError(404, {
            message: "Token not found",
            details: "No token exists with the ID from the provided token in the database.",
        });
    }

    if (tokenRecord.expiresAt <= new Date()) {
        throw new AppError(401, {
            message: "Token expired",
            details: "Provided token is already expired and no longer valid.",
        });
    }

    const { hashedSecret, userId, emailAddressId } = tokenRecord;
    if (!constantTimeCompare(hmacSHA256(secret), hashedSecret)) {
        throw new AppError(401, {
            message: "Invalid secret",
            details: "Secret from the provided token doesn't match the stored one.",
        });
    }

    if (!emailAddressId) {
        throw new AppError(422, {
            message: "Data inconsistency",
            details: "No email address found linked with the token.",
        });
    }

    const emailRecord = await prisma.emailAddress.findFirst({
        where: {
            id: emailAddressId,
        },
        select: {
            id: true,
            isVerified: true,
        },
    });

    if (!emailRecord) {
        throw new AppError(404, {
            message: "Email not found",
            details: "No email address exists associated with the token in the database.",
        });
    }

    if (emailRecord.isVerified) {
        throw new AppError(409, {
            message: "Email is already verified",
            details: "Provided email address has already been verified.",
        });
    }

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
        await tx.token.delete({
            where: {
                id: tokenId,
            },
        });
        await tx.emailAddress.update({
            where: {
                id: emailRecord.id,
            },
            data: {
                isVerified: true,
            },
        });
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
                        id: emailRecord.id,
                    },
                },
            },
        });
        await tx.auditLog.create({
            data: {
                event: "EMAIL_VERIFIED",
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
        sessionId,
        userId,
        refreshToken,
    };
};
