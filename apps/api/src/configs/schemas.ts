import z from "zod";

export const envSchema = z
    .object({
        NODE_ENV: z.enum(["development", "test", "production"]),
        PORT: z.string().transform(Number).default(8888),
        WEB_ORIGIN: z.url(),
        API_ORIGIN: z.url().optional(),
    })
    .superRefine((arg, ctx) => {
        if (!arg.API_ORIGIN) {
            if (arg.NODE_ENV == "production") {
                ctx.addIssue({
                    message: "Invalid input: expected string, received undefined",
                    code: "custom",
                    path: ["API_ORIGIN"],
                });
            } else {
                arg.API_ORIGIN = `http://localhost:${arg.PORT}`;
            }
        }
    });
