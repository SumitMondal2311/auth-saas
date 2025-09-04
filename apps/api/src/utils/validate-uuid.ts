import { z } from "zod";

export const validateUUID = (value: string): boolean => {
    const uuidSchema = z.uuid();
    return !!uuidSchema.safeParse(value).success;
};
