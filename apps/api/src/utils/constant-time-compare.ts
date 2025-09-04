import { timingSafeEqual } from "crypto";

export const constantTimeCompare = (strA: string, strB: string): boolean => {
    const bufA = Buffer.from(strA);
    const bufB = Buffer.from(strB);

    if (bufA.length !== bufB.length) {
        timingSafeEqual(Buffer.from(new Array(bufB.length).fill(" ")), bufB);
        return false;
    }

    return timingSafeEqual(bufA, bufB);
};
