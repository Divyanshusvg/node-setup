import { Router } from "express";
import { isAdmin } from "../middlewares/auth.middleware.js";
import { loginAdmin,
    getLoginAdmin,
    dashboredAdmin,
    verifyOtpAdmin,
    logoutAdmin,
    deleteUser} from "../controllers/admin/admin.controller.js"


const router = Router()

router.route("/").get(isAdmin , dashboredAdmin)
router.route("/loginAdmin").post(loginAdmin)
router.route("/logoutAdmin").get(isAdmin,logoutAdmin)
router.route("/login").get(getLoginAdmin)
router.route("/verifyOtpAdmin").post(verifyOtpAdmin)
router.route("/deleteUser").post(isAdmin,deleteUser)
export default router
