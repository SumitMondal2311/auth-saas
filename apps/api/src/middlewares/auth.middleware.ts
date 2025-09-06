import { prisma } from "@auth-saas/database";
import { NextFunction, Request, Response } from "express";
import { verifyToken } from "../lib/jwt.js";
import { AppError } from "../utils/app-error.js";
import { handleAsync } from "../utils/handle-async.js";

const authMiddleware = async (req: Request, _res: Response, next: NextFunction) => {
    const authHeader = req.headers["authorization"];
    if (!authHeader) {
        return next(
            new AppError(401, {
                message: "Missing authorization header",
                details: "Request doesn't contain any authorization header.",
            })
        );
    }

    const [schema, accessToken] = authHeader.split(" ");
    if (schema !== "Bearer" || !accessToken) {
        return next(
            new AppError(401, {
                message: "Invalid authorization header",
                details: "Expected format: Bearer <access_token>",
            })
        );
    }

    console.log("auth-middleware");
    const { payload } = await verifyToken(accessToken);
    console.log(payload);
    const { sub, sid, typ } = payload;
    if (!sub || !sid || typ !== "access") {
        return next(
            new AppError(401, {
                message: "Invalid access token claims",
                details: "Required claims are invalid or missing in the access token payload.",
            })
        );
    }

    const sessionRecord = await prisma.session.findUnique({
        where: {
            userId: sub,
            id: sid,
        },
        select: {
            id: true,
        },
    });

    if (!sessionRecord) {
        throw new AppError(401, {
            message: "Session not found",
            details: "No active session found in the database matches the access token claims.",
        });
    }

    req.authData = {
        userId: sub,
        sessionId: sid,
    };

    next();
};

export const authMiddlewareHandler = handleAsync(authMiddleware);
