import { Router } from "express";
import {
    registerUser,
    verifyOtp,
    login,
    logoutUser
} from "../controllers/user.controller.js";
import {upload} from "../middlewares/multer.middleware.js"
import { verifyJWT } from "../middlewares/auth.middleware.js";


const router = Router()


router.route("/register").post(registerUser)
router.route("/verifyOtp").post(verifyOtp)
router.route("/login").post(login)
router.route("/logoutUser").get(verifyJWT,logoutUser)

export default router