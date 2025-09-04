import { Router } from "express";
import { signupRouteHandler } from "../modules/signup/signup.controller.js";
import { verifyEmailRouteHandler } from "../modules/verify-email/verify-email.controller.js";
import { loginRouteHandler } from "../modules/login/login.controller.js";

export const authRouter: Router = Router();

authRouter.post("/signup", signupRouteHandler);
authRouter.post("/login", loginRouteHandler);
authRouter.post("/verify-email", verifyEmailRouteHandler);
