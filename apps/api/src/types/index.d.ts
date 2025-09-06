import "express";

declare global {
    namespace Express {
        interface Request {
            authData?: {
                sessionId: string;
                userId: string;
            };
        }
    }
}
