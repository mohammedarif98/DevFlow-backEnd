import express from "express";
import { authenticateUser } from "../middlewares/authMiddleware.js";
import { getUserProfile, googleAuth, loginUser, logoutUser, refreshAccessToken, registerUser, resendOTP, verifyOTP } from "../controllers/authController.js";

const router = express.Router();

// ----------------- POST methods --------------------
router.post("/register-user", registerUser);
router.post("/verifyOTP", verifyOTP);
router.get('/resendOTP', resendOTP);
router.post("/login-user", loginUser);
router.post("/google-login", googleAuth);
router.post("/logout-user", logoutUser);
router.post("/user-refresh-token", refreshAccessToken);


// ------------------ GET methods --------------------
router.get('/profile', authenticateUser, getUserProfile);


export default router;
















// router.get('/protected-route', authenticateUser, catchAsync(async(req, res) => {
//   res.status(200).json({
//       status: 'success',
//       message: 'You have accessed a protected route!',
//       user: req.user,
//   });
// }));

// router.get("/test", catchAsync(async (req, res) => {
//   const user = "arif";
//   user
//     ? res.status(200).json({ status: "sucess", user })
//     : res.status(500).json({ status: "error", message: "user not found" });
// }));