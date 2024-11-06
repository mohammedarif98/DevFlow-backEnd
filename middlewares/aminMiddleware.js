import { catchAsync } from "../error/catchAsync.js";
import jwt from 'jsonwebtoken';
import Admin from '../models/adminModel.js';
import AppError from "../utils/appError.js"; 



export const authenticateAdmin = catchAsync(async(req, res, next) => {
    
    const token = req.cookies['access-token'] || req.headers['authorization']?.splite(' ')[1];
    if( !token ) return next( new AppError(" You are not Logged in! please log",401));

    try{
        const decode = jwt.verify( token, process.env.JWT_ACCESS_TOKEN_SECRET_KEY);

        const admin = await Admin.findById(decode.id).select('-password');
        if(!admin) return next(new AppError("Admin not found",401));

        req.admin = admin;
        next();
    }catch(error){
        console.log("Error in admin authentication middleware",error.message);
        return next(new AppError("Token is invalid or expired",403));
    }
});