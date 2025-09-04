import { CreateEmailResponseSuccess, Resend } from "resend";
import { env } from "../configs/env.js";

const resend = new Resend(env.RESEND_API_KEY);

export const resendClient = async ({
    subject,
    email,
    template,
}: {
    subject: string;
    email: string;
    template: string;
}): Promise<CreateEmailResponseSuccess> => {
    const { data, error } = await resend.emails.send({
        from: "Acme <onboarding@resend.dev>",
        to: email,
        subject,
        html: template,
    });

    if (error) {
        console.error(error.message);
        process.exit(1);
    }

    return data;
};
