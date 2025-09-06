import { NextFunction, Request, Response } from "express";
import { IS_PRODUCTION } from "../../configs/constants.js";
import { AppError } from "../../utils/app-error.js";
import { handleAsync } from "../../utils/handle-async.js";
import { normalizedIP } from "../../utils/normalized-ip.js";
import { logoutService } from "./logout.service.js";

const logoutController = async (req: Request, res: Response, next: NextFunction) => {
    const refreshToken = req.cookies["__HOST-auth-session"] as string;
    if (!refreshToken) {
        return next(
            new AppError(401, {
                message: "Missing refresh token",
            })
        );
    }

    await logoutService({
        userAgent: req.headers["user-agent"],
        ipAddress: normalizedIP(req.ip || "unknown"),
        refreshToken,
    });

    res.status(200)
        .cookie("__HOST-auth-session", "", {
            secure: IS_PRODUCTION,
            httpOnly: true,
            maxAge: 0,
            sameSite: "strict",
        })
        .json({ message: "Logged out successfully" });
};

export const logoutRouteHandler = handleAsync(logoutController);
