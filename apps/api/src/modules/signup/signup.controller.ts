import { NextFunction, Request, Response } from "express";
import { authSchema } from "../../configs/schemas.js";
import { AppError } from "../../utils/app-error.js";
import { handleAsync } from "../../utils/handle-async.js";
import { normalizedIP } from "../../utils/normalized-ip.js";
import { signupService } from "./signup.service.js";

const signupController = async (req: Request, res: Response, next: NextFunction) => {
    const parsedSchema = authSchema.safeParse(req.body);
    if (!parsedSchema.success) {
        return next(
            new AppError(400, {
                message: parsedSchema.error.issues[0].message,
            })
        );
    }

    const { email, password } = parsedSchema.data;
    await signupService({
        userAgent: req.headers["user-agent"],
        ipAddress: normalizedIP(req.ip || "unknown"),
        email,
        password,
    });

    res.status(201).json({
        message:
            "Signed up successfully. A verification link has been sent to your email, please check your inbox and verify your email.",
    });
};

export const signupRouteHandler = handleAsync(signupController);
