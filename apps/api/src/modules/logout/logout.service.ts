import { prisma } from "@auth-saas/database";
import { env } from "../../configs/env.js";
import { verifyToken } from "../../lib/jwt.js";
import { redis } from "../../lib/redis.js";
import { AppError } from "../../utils/app-error.js";
import { redisKey } from "../../utils/redis-keys.js";

export const logoutService = async ({
    refreshToken,
    ipAddress,
    userAgent,
}: {
    refreshToken: string;
    ipAddress?: string;
    userAgent?: string;
}) => {
    const { payload } = await verifyToken(refreshToken);
    const { jti, sub, exp, sid, typ } = payload;
    if (!sid || !sub || !jti || typ !== "refresh") {
        throw new AppError(401, {
            message: "Invalid refresh token claims",
        });
    }

    const session = await prisma.session.findFirst({
        where: {
            refreshTokenId: jti,
            id: sid,
            userId: sub,
        },
    });

    if (!session) {
        throw new AppError(404, {
            message: "Session not found",
        });
    }

    await prisma.$transaction(async (tx) => {
        await tx.session.update({
            where: {
                isRevoked: false,
                id: sid,
                userId: sub,
            },
            data: {
                isRevoked: true,
            },
        });
        await tx.auditLog.create({
            data: {
                event: "LOGGED_OUT",
                ipAddress,
                userAgent,
                user: {
                    connect: {
                        id: sub,
                    },
                },
            },
        });
    });

    await redis.set(
        redisKey.blacklistJti(jti),
        "revoked",
        "EX",
        exp
            ? Math.ceil(Math.max(0, exp - Math.floor(Date.now() / 1000)))
            : env.REFRESH_TOKEN_EXPIRY * 1000
    );
};
