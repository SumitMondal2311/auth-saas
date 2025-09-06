import { createPrivateKey, createPublicKey } from "crypto";
import { existsSync, readFileSync } from "fs";
import { JWTPayload, JWTVerifyResult, SignJWT, errors, jwtVerify } from "jose";
import { resolve } from "path";
import { env } from "../configs/env.js";
import { AppError } from "../utils/app-error.js";

const secretsDir = resolve(process.cwd(), "secrets");
if (existsSync(secretsDir) === false) {
    console.error("Missing secrets directory");
    process.exit(1);
}

const privatePemPath = resolve(secretsDir, "private.pem");
const publicPemPath = resolve(secretsDir, "public.pem");
if (!existsSync(privatePemPath) || !existsSync(publicPemPath)) {
    console.error("Missing private.pem or public.pem file");
    process.exit(1);
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
        if (
            error instanceof errors.JWTInvalid ||
            error instanceof errors.JWSInvalid ||
            error instanceof errors.JWSSignatureVerificationFailed ||
            error instanceof errors.JWTExpired ||
            error instanceof errors.JWTClaimValidationFailed
        ) {
            throw new AppError(401, {
                message: error.message,
            });
        }

        throw error;
    }
};
