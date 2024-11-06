import express from "express";
import { adminLogin, adminLogout, refreshAdminAccessToken } from "../controllers/adminController.js";
import { authenticateAdmin } from "../middlewares/aminMiddleware.js";
import { catchAsync } from "../error/catchAsync.js";

const router = express.Router();



router.post('/login-admin',adminLogin);
router.post('/logout-admin',adminLogout);
router.post('/refresh-token',refreshAdminAccessToken);


router.get('/protected-route', authenticateAdmin, catchAsync(async(req, res) => {
    res.status(200).json({
        status: 'success',
        message: 'You have accessed a protected route!',
        user: req.admin,
    });
}));



export default router;