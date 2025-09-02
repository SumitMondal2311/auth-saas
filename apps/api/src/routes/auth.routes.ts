import { Router } from "express";
import { signupRouteHandler } from "../modules/signup/signup.controller.js";

export const authRouter: Router = Router();

authRouter.post("/signup", signupRouteHandler);
