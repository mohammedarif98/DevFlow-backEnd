import { catchAsync } from "../error/catchAsync.js";
import User from "../models/userModel.js";
import OTP from "../models/otpModel.js";
import AppError from "../utils/appError.js";
import { generateOTP } from "../utils/generateOTP.js";
import sendMail from "../utils/sendEmail.js";
import { generateAccessToken, generateRefreshToken } from "../utils/jwt.js";
import comparePassword from '../utils/comparePassword.js'; 
import jwt from "jsonwebtoken";



// --------------- User Registration ----------------
export const registerUser = catchAsync(async (req, res, next) => {
    const { username,email,password,confirmPassword } = req.body;

    if( !username || !email || !password || !confirmPassword )  return next(new AppError("Fill all fields", 400));
    if( password !== confirmPassword ) return next(new AppError("Passwords do not match",400));

    const existUser = await User.findOne({ email });
    if( existUser ) return next(new AppError("User is already exist",400));

    const otp = generateOTP();
    const otpExpires = Date.now() + 5 * 60 * 1000;          // otp expires after 5 min

    const user = new User({
        username,
        email,
        password,
        confirmPassword
    });
    await user.save();

    await OTP.create({
        userId: user._id,
        otp,
        otpExpires,
    });

    await sendMail( email, 'OTP For Email Verification', `<h1>Your OTP is: ${otp}</h1>`);

    return res.status( 201 ).json({
        status: 'success',
        message: 'User registered. OTP sent to email',
    });
});


// ---------------- email OTP Verification --------------------
export const verifyOTP = catchAsync( async (req, res, next) => {
    const { otp } = req.body;

    if( !otp ) return next(new AppError("OTP is required! please fill OTP",400));

    const findOTP = await OTP.findOne({ otp, otpExpires: { $gt: Date.now() }});
    
    if(!findOTP) return next(new AppError("Invalid or expired OTP", 400));

    const user = await User.findById( findOTP.userId );
    if (!user) return next(new AppError("User not found.", 404));
    
    user.isVerified = true;             
    await user.save({ validateBeforeSave: false });

    // Clear the OTP data from the database after successful verification
    await OTP.findByIdAndDelete( findOTP._id );
   
    res.status( 200 ).json({
        status: 'success',
        message: 'Email verified and Authenticated successfully!',
    });
});



// ------------------ Resend email OTP -----------------
export const resendOTP = catchAsync(async (req, res, next) => {
    const { email } = req.body;

    if (!email) return next(new AppError("Email is required!", 400));

    const user = await User.findOne({ email });
    if (!user) return next(new AppError("User not found.", 404));

    const existingOTP = await OTP.findOne({ userId: user._id });
    if (existingOTP && existingOTP.otpExpires > Date.now()) return next(new AppError("OTP has not yet expired. Please check your email for the current OTP.", 400));

    const otp = generateOTP();
    const otpExpires = Date.now() + 5 * 60 * 1000; 

    // Create or update the OTP record
    if (existingOTP) {
        existingOTP.otp = otp;
        existingOTP.otpExpires = otpExpires;
        await existingOTP.save();
    } else {
        await OTP.create({
            userId: user._id,
            otp,
            otpExpires,
        });
    }

    await sendMail(email, 'New OTP for Email Verification', `<h1>Your new OTP is: ${otp}</h1>`);

    res.status( 200 ).json({
        status: 'success',
        message: 'New OTP has been sent to your email.',
    });
});



// ------------------ User Login -------------------
export const loginUser = catchAsync( async (req, res, next) => {

    const { email, password } = req.body;
    if( !email || !password ) return next( new AppError("Please provide email and password",400));
        
    const user = await User.findOne({ email }).select('+password');
    if( !user ) return next( new AppError("User does not exist",404));
    
    if ( !user.isVerified ) return next(new AppError("Your email has not been verified. Verify email.", 403));

    const isPasswordCorrect = await comparePassword( password, user.password );
    if ( !isPasswordCorrect ) return next(new AppError("Invalid credentials", 401));

    const accessToken = generateAccessToken( user._id );
    const refreshToken =  generateRefreshToken( user._id );

    const accessTokenCookieOptions = {  
        expires: new Date( Date.now() + 15 * 60 * 1000 ), 
        httpOnly: true,
        secure: process.env.NODE_ENV === "production", 
        sameSite: process.env.NODE_ENV === "production" ? "none" : "Lax", 
    };

    const refreshTokenCookieOptions = {
        expires: new Date( Date.now() + 24 * 60 * 60 * 1000 ), 
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "none" : "Lax",
    };
    
    res.cookie( "access-token", accessToken , accessTokenCookieOptions );
    res.cookie( "refresh-token", refreshToken , refreshTokenCookieOptions );


    return res.status( 200 ).json({
        status: "success",
        message: "Login successful",
        accessToken,
        refreshToken,
        user: {
            id: user._id,
            username: user.username,
            email: user.email,
            isVerified: user.isVerified,
        },
      });
    
})


// ------------------ User Logout -------------------
export const logoutUser = catchAsync(async (req, res, next) => {
    res.clearCookie("access-token", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "none" : "Lax",
    });
    
    res.clearCookie("refresh-token", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "none" : "Lax",
    });
    
    return res.status( 200 ).json({
        status: "success",
        message: "Logout successful",
    });
});


// ------------------ refresh the access token -------------------
export const refreshAccessToken = catchAsync(async (req, res, next) => {
    
    const refreshToken = req.cookies['refresh-token'];
    if (!refreshToken) return next(new AppError("Refresh token is missing", 403));
    try {
        // console.log("Refresh Token: ", refreshToken);
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_TOKEN_SECRET_KEY);
      
        const user = await User.findById(decoded.id).select('-password');                                   // Check if user still exists
        if (!user) return next(new AppError("User not found", 401));
    
        const newAccessToken = generateAccessToken(user._id);                           // Generate a new access token

        const cookieOptions = {
                expires: new Date(Date.now() + 15 * 60 * 1000), 
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'Lax',
            };

        res.cookie('access-token', newAccessToken, cookieOptions);
    
        return res.status(200).json({
            status: "success",
            message: 'Access token refreshed successfully',
            accessToken: newAccessToken,
        });
    } catch (err) {
        console.error("Token Verification Error: ", err);
        return next(new AppError("Refresh token is invalid or has expired", 403));
    }
  });


// ------------------  -------------------
// ------------------  -------------------
// ------------------  -------------------
// ------------------  -------------------
