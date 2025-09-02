import { Router } from "express";
import { healthController } from "../modules/health/health.controller.js";
import { authRouter } from "./auth.routes.js";

export const router: Router = Router();

router.get("/health", healthController);
router.use("/auth", authRouter);
