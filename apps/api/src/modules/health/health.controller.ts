import { Request, Response } from "express";

export const healthController = (_req: Request, res: Response) => {
    return res.status(200).json({
        message: "OK",
        uptime: process.uptime(),
    });
};
