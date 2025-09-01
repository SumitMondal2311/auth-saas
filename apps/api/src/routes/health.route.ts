import { Request, Response, Router } from "express";

export const healthRouter: Router = Router();

healthRouter.get("/", (_req: Request, res: Response) => {
    res.status(200).json({
        uptime: process.uptime(),
        message: "OK",
    });
});
