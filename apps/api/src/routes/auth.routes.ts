import { Router } from "express";
import { loginRouteHandler } from "../modules/login/login.controller.js";
import { signupRouteHandler } from "../modules/signup/signup.controller.js";

export const authRouter: Router = Router();

authRouter.post("/signup", signupRouteHandler);
authRouter.post("/login", loginRouteHandler);
