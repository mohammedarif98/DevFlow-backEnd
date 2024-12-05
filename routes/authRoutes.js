import express from "express";
import { authenticateUser } from "../middlewares/authMiddleware.js";
import { addComment, bookmarkBlog, createBlogPost, deleteComments, deleteReply, editBlogPost, followCategory, followUser, getAllBlogs, getAllCategory, getAllUser, getBlogDetail, getBlogLikeCount, getCategoryPage, getComments, getFollowedUsers, getUserBlogs, getUserProfile, getUsersPage, googleAuth, likeBlog, loginUser, logoutUser, refreshAccessToken, registerUser, repliesToComments, resendOTP, unbookmarkBlog, unfollowCategory, unfollowUser, UnlikeBlog, updateUserProfile, verifyOTP } from "../controllers/authController.js";
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
router.post('/like-blog/:blogId',authenticateUser, likeBlog);
router.post('/bookmark-blog/:blogId',authenticateUser, bookmarkBlog);
router.post('/add-comment-blog/:blogId',authenticateUser, addComment);
router.post('/blogs/:blogId/comments/:commentId/replies', authenticateUser, repliesToComments);
router.post('/follow-user/:userIdToFollow', authenticateUser , followUser);
router.post('/follow-category/:categoryId', authenticateUser , followCategory);


// ------------------ GET methods --------------------
router.get('/profile', authenticateUser, getUserProfile);
router.get('/get-category', getAllCategory);
router.get('/get-blogs',getAllBlogs);
router.get('/get-blog-detail/:blogId',getBlogDetail);
router.get('/get-user-blog', authenticateUser ,getUserBlogs);
router.get('/get-like-count/:blogId', getBlogLikeCount);
router.get('/get-comments/:blogId',authenticateUser , getComments);
router.get('/get-users',authenticateUser , getAllUser);
router.get('/followed-users', authenticateUser, getFollowedUsers );
router.get('/users-datails/:usersId', authenticateUser, getUsersPage);
router.get('/categories-datails/:categoryId', authenticateUser, getCategoryPage);


// ------------------ PUT methods --------------------
router.put('/update-profile',authenticateUser, upload.single('profilePhoto'), updateUserProfile);
router.put('/update-blog-post/:blogId', authenticateUser, upload.single('coverImage'), editBlogPost);


// --------------------- DELETE method -----------------
router.delete('/unlike-blog/:blogId',authenticateUser, UnlikeBlog);
router.delete('/unbookmark-blog/:blogId',authenticateUser, unbookmarkBlog);
router.delete('/delete-comment/:commentId', authenticateUser, deleteComments);
router.delete('/delete-comment/:commentId/reply/:replyId', authenticateUser, deleteReply);
router.delete('/unfollow-user/:userIdToUnfollow', authenticateUser , unfollowUser);
router.delete('/unfollow-category/:categoryId', authenticateUser , unfollowCategory);


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