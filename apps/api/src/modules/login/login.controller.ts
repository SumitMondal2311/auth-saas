import { NextFunction, Request, Response } from "express";
import { IS_PRODUCTION } from "../../configs/constants.js";
import { env } from "../../configs/env.js";
import { authSchema } from "../../configs/schemas.js";
import { signToken } from "../../lib/jwt.js";
import { addDurationToNow } from "../../utils/add-duration-to-now.js";
import { AppError } from "../../utils/app-error.js";
import { handleAsync } from "../../utils/handle-async.js";
import { normalizedIP } from "../../utils/normalized-ip.js";
import { loginService } from "./login.service.js";

const loginController = async (req: Request, res: Response, next: NextFunction) => {
    const parsedSchema = authSchema.safeParse(req.body);
    if (!parsedSchema.success) {
        return next(
            new AppError(400, {
                message: parsedSchema.error.issues[0].message,
                details: "Invalid input",
            })
        );
    }

    const { email, password } = parsedSchema.data;
    const { refreshToken, userId, sessionId } = await loginService({
        userAgent: req.headers["user-agent"],
        ipAddress: normalizedIP(req.ip || "unknown"),
        email,
        password,
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
                addDurationToNow(env.REFRESH_TOKEN_EXPIRY * 1000)
            ),
            message: "Logged in successfully",
        });
};

export const loginRouteHandler = handleAsync(loginController);
