import express from "express";
import { catchAsync } from "../error/catchAsync.js";
import { loginUser, logoutUser, refreshAccessToken, registerUser, resendOTP, verifyOTP } from "../controllers/authController.js";
import { authenticateUser } from "../middlewares/authMiddleware.js";


const router = express.Router();


router.post("/register-user", registerUser);
router.post("/verifyOTP", verifyOTP);
router.post("/resendOTP", resendOTP);
router.post("/login-user", loginUser);
router.post("/logout-user", logoutUser);
router.post("/refresh-token", refreshAccessToken);


router.get('/protected-route', authenticateUser, catchAsync(async(req, res) => {
    res.status(200).json({
        status: 'success',
        message: 'You have accessed a protected route!',
        user: req.user,
    });
}));


router.get(
  "/test",
  catchAsync(async (req, res) => {
    const user = "arif";
    user
      ? res.status(200).json({ status: "sucess", user })
      : res.status(500).json({ status: "error", message: "user not found" });
  })
);



export default router;
