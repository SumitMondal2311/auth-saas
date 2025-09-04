import { NextFunction, Request, Response } from "express";
import { IS_PRODUCTION } from "../../configs/constants.js";
import { env } from "../../configs/env.js";
import { signToken } from "../../lib/jwt.js";
import { addDurationToNow } from "../../utils/add-duration-to-now.js";
import { AppError } from "../../utils/app-error.js";
import { handleAsync } from "../../utils/handle-async.js";
import { normalizedIP } from "../../utils/normalized-ip.js";
import { validateUUID } from "../../utils/validate-uuid.js";
import { verifyEmailService } from "./verify-email.service.js";

const verifyEmailController = async (req: Request, res: Response, next: NextFunction) => {
    const { token } = req.query;
    if (!token || typeof token !== "string") {
        return next(
            new AppError(400, {
                message: "Invalid or missing token",
                details: "Provided token is either missing or not a string.",
            })
        );
    }

    const [tokenId, secret] = decodeURIComponent(token).split(".");
    if (!tokenId || !secret) {
        throw new AppError(400, {
            message: "Invalid token format",
            details: "Provided token is not in the correct format",
        });
    }

    if (validateUUID(tokenId) === false) {
        throw new AppError(400, {
            message: "Invalid token ID",
            details: "ID from the provided token is not a valid UUID",
        });
    }

    const { refreshToken, userId, sessionId } = await verifyEmailService({
        userAgent: req.headers["user-agent"],
        ipAddress: normalizedIP(req.ip || "unknown"),
        secret,
        tokenId,
    });

    res.status(200)
        .cookie("__refresh_token__", refreshToken, {
            secure: IS_PRODUCTION,
            httpOnly: true,
            maxAge: env.REFRESH_TOKEN_EXPIRY * 1000,
            sameSite: "strict",
        })
        .json({
            accessToken: await signToken(
                {
                    typ: "access",
                    sub: userId,
                    sid: sessionId,
                },
                addDurationToNow(env.ACCESS_TOKEN_EXPIRY * 1000)
            ),
            message: "Email verified successfully.",
        });
};

export const verifyEmailRouteHandler = handleAsync(verifyEmailController);
