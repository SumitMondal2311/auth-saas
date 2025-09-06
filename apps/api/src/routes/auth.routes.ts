import { Router } from "express";
import { authMiddlewareHandler } from "../middlewares/auth.middleware.js";
import { loginRouteHandler } from "../modules/login/login.controller.js";
import { logoutRouteHandler } from "../modules/logout/logout.controller.js";
import { signupRouteHandler } from "../modules/signup/signup.controller.js";
import { verifyEmailRouteHandler } from "../modules/verify-email/verify-email.controller.js";

export const authRouter: Router = Router();

authRouter.post("/signup", signupRouteHandler);
authRouter.post("/login", loginRouteHandler);
authRouter.post("/verify-email", verifyEmailRouteHandler);
authRouter.use(authMiddlewareHandler);
authRouter.post("/logout", logoutRouteHandler);
