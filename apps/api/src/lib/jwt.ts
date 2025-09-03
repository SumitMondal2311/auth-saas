import { createPrivateKey, createPublicKey } from "crypto";
import { existsSync, readFileSync } from "fs";
import { JWTPayload, JWTVerifyResult, SignJWT, errors, jwtVerify } from "jose";
import { resolve } from "path";
import { env } from "../configs/env.js";
import { AppError } from "../utils/app-error.js";

const secretsDir = resolve(process.cwd(), "secrets");
if (existsSync(secretsDir) === false) {
    throw new AppError(401, {
        message: "Missing secrets directory",
        details: "Missing secrets directory",
    });
}

const privatePemPath = resolve(secretsDir, "private.pem");
const publicPemPath = resolve(secretsDir, "public.pem");
if (!existsSync(privatePemPath) || !existsSync(publicPemPath)) {
    throw new AppError(401, {
        message: "No pem files found",
        details: "Missing private.pem or public.pem file",
    });
}

const privateKey = createPrivateKey(readFileSync(privatePemPath, "utf8"));
const publicKey = createPublicKey(readFileSync(publicPemPath, "utf8"));

export interface AuthJWTPayload extends JWTPayload {
    sid?: string;
    typ?: "access" | "refresh";
}

export const signToken = (
    payload: AuthJWTPayload,
    expirationTime: number | string | Date
): Promise<string> => {
    return new SignJWT({
        ...payload,
        iss: env.JWT_ISS,
        kid: env.JWT_KID,
        aud: env.JWT_AUD,
    })
        .setProtectedHeader({ alg: "RS256" })
        .setNotBefore(0)
        .setIssuedAt()
        .setExpirationTime(expirationTime)
        .sign(privateKey);
};

export const verifyToken = async (token: string): Promise<JWTVerifyResult<AuthJWTPayload>> => {
    try {
        return await jwtVerify(token, publicKey);
    } catch (error) {
        if (error instanceof errors.JWTExpired) {
            throw new AppError(401, {
                message: "Token has expired",
                details: error.message,
            });
        } else if (error instanceof errors.JWTClaimValidationFailed) {
            throw new AppError(401, {
                message: "Token is not yet valid",
                details: error.message,
            });
        } else if (error instanceof errors.JWTInvalid) {
            throw new AppError(401, {
                message: "Token is either malformed or broken",
                details: error.message,
            });
        }

        throw error;
    }
};
