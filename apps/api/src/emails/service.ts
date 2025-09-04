import { env } from "../configs/env.js";
import { resendClient } from "./client.js";
import { verifyEmailTemplate } from "./templates/verify-email.js";

export const sendVerificationEmail = (email: string, token: string) => {
    return resendClient({
        subject: "Please confirm your email address",
        email,
        template: verifyEmailTemplate(env.WEB_ORIGIN + "/verify-email?token=" + token),
    });
};
