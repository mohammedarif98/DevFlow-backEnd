import express from "express";
import { authenticateAdmin } from "../middlewares/adminMiddleware.js";
import { addCategory, adminLogin, adminLogout, blockUser, editCategory, getAllUsers, getCategory, refreshAdminAccessToken, unblockUser } from "../controllers/adminController.js";
import { upload } from "../middlewares/multer/multer.js";

const router = express.Router();



// ------------------ GET methods --------------------
router.get('/list-users', authenticateAdmin, getAllUsers);
router.get('/list-category', authenticateAdmin, getCategory);


// ----------------- POST methods --------------------
router.post('/login-admin', adminLogin);
router.post('/logout-admin', adminLogout);
router.post('/admin-refresh-token', refreshAdminAccessToken);
router.post('/categories', authenticateAdmin, upload.single('categoryImage'), addCategory);

// ------------------ PUT methods --------------------
router.put('/block-user/:userId', authenticateAdmin, blockUser);
router.put('/unblock-user/:userId', authenticateAdmin, unblockUser);
router.put('/edit-category/:categoryId', authenticateAdmin, upload.single('categoryImage'), editCategory);
 



export default router;

















// router.get('/protected-route', authenticateAdmin, catchAsync(async(req, res) => {
//     res.status(200).json({
//         status: 'success',
//         message: 'You have accessed a protected route!',
//         user: req.admin,
//     });
// }));