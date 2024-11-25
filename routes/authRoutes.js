import express from "express";
import { authenticateUser } from "../middlewares/authMiddleware.js";
import { createBlogPost, editBlogPost, getAllBlogs, getBlogDetail, getUserProfile, googleAuth, loginUser, logoutUser, refreshAccessToken, registerUser, resendOTP, updateUserProfile, verifyOTP } from "../controllers/authController.js";
import { upload } from "../middlewares/multer/multer.js";

const router = express.Router();


// ----------------- POST methods --------------------
router.post("/register-user", registerUser);
router.post("/verifyOTP", verifyOTP);
router.get('/resendOTP', resendOTP);
router.post("/login-user", loginUser);
router.post("/google-login", googleAuth);
router.post("/logout-user", logoutUser);
router.post("/user-refresh-token", refreshAccessToken);
router.post('/blog-post', authenticateUser, upload.single('coverImage'), createBlogPost);


// ------------------ GET methods --------------------
router.get('/profile', authenticateUser, getUserProfile);
router.get('/get-blogs',getAllBlogs);
router.get('/get-blog-detail/:blogId',getBlogDetail);


// ------------------ PUT methods --------------------
router.put("/update-profile",authenticateUser, upload.single('profilePhoto'), updateUserProfile);
router.put('/update-blog-post/:blogId', authenticateUser, upload.single('coverImage'), editBlogPost);


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