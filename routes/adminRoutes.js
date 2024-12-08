import express from "express";
import { authenticateAdmin } from "../middlewares/adminMiddleware.js";
import { addCategory, adminLogin, adminLogout, blockBlogs, blockUser, editCategory, getAllUsers, getBlogDetail, getBlogList, getCategory, getDashBoard, refreshAdminAccessToken, unblockBlogs, unblockUser } from "../controllers/adminController.js";
import { upload } from "../middlewares/multer/multer.js";

const router = express.Router();



// ------------------ GET methods --------------------
router.get('/list-users', authenticateAdmin, getAllUsers);
router.get('/list-category', authenticateAdmin, getCategory);
router.get('/list-blogs', authenticateAdmin, getBlogList);
router.get('/blog-detail/:blogId', authenticateAdmin, getBlogDetail);
router.get('/dashboard', authenticateAdmin, getDashBoard);


// ----------------- POST methods --------------------
router.post('/login-admin', adminLogin);
router.post('/logout-admin', adminLogout);
router.post('/admin-refresh-token', refreshAdminAccessToken);
router.post('/categories', authenticateAdmin, upload.single('categoryImage'), addCategory);

// ------------------ PUT methods --------------------
router.put('/block-user/:userId', authenticateAdmin, blockUser);
router.put('/unblock-user/:userId', authenticateAdmin, unblockUser);
router.put('/edit-category/:categoryId', authenticateAdmin, upload.single('categoryImage'), editCategory);
router.put('/block-blog/:blogId',authenticateAdmin, blockBlogs);
router.put('/unblock-blog/:blogId', authenticateAdmin, unblockBlogs);



export default router;

















// router.get('/protected-route', authenticateAdmin, catchAsync(async(req, res) => {
//     res.status(200).json({
//         status: 'success',
//         message: 'You have accessed a protected route!',
//         user: req.admin,
//     });
// }));