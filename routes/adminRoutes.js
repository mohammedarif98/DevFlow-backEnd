import express from "express";
import { authenticateAdmin } from "../middlewares/adminMiddleware.js";
import { adminLogin, adminLogout, getAllUsers, refreshAdminAccessToken } from "../controllers/adminController.js";

const router = express.Router();

// ----------------- POST methods --------------------
router.post('/login-admin',adminLogin);
router.post('/logout-admin',adminLogout);
router.post('/admin-refresh-token',refreshAdminAccessToken);


// ------------------ GET methods --------------------
router.get('/list-users',authenticateAdmin, getAllUsers);





export default router;

















// router.get('/protected-route', authenticateAdmin, catchAsync(async(req, res) => {
//     res.status(200).json({
//         status: 'success',
//         message: 'You have accessed a protected route!',
//         user: req.admin,
//     });
// }));