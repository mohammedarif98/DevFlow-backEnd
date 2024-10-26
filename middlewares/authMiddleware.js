import { catchAsync } from "../error/catchAsync.js";
import jwt from 'jsonwebtoken';
import User from '../models/userModel.js';
import AppError from "../utils/appError.js"; 
 


export const authenticateUser = catchAsync( async( req, res, next) => {

    const token = req.cookies['access-token'] || req.headers['authorization']?.split(' ')[1];
    if ( !token ) return next( new AppError('You are not logged in! Please log .', 401));

    try {
        const decoded = jwt.verify( token, process.env.JWT_ACCESS_TOKEN_SECRET_KEY );

        const user = await User.findById(decoded.id).select('-password');
        if (!user) return next(new AppError('User not found', 401));

        req.user = user;   //* Attach the user to the request object
        next();
    }catch(error){
        console.log("Error in user authentication middleware",error.message);
        return next(new AppError("Token is invalid or has expired", 403));
    }
})