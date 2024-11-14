import express from "express";
import { authenticateAdmin } from "../middlewares/adminMiddleware.js";
import { adminLogin, adminLogout, blockUser, getAllUsers, refreshAdminAccessToken, unblockUser } from "../controllers/adminController.js";

const router = express.Router();



// ------------------ GET methods --------------------
router.get('/list-users',authenticateAdmin, getAllUsers);


// ----------------- POST methods --------------------
router.post('/login-admin',adminLogin);
router.post('/logout-admin',adminLogout);
router.post('/admin-refresh-token',refreshAdminAccessToken);


// ------------------ PUT methods --------------------
router.put('/block-user/:userId',authenticateAdmin, blockUser);
router.put('/unblock-user/:userId',authenticateAdmin, unblockUser);




export default router;

















// router.get('/protected-route', authenticateAdmin, catchAsync(async(req, res) => {
//     res.status(200).json({
//         status: 'success',
//         message: 'You have accessed a protected route!',
//         user: req.admin,
//     });
// }));