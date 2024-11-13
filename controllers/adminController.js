import { catchAsync } from "../error/catchAsync.js";
import Admin from "../models/adminModel.js";
import User from "../models/userModel.js";
import AppError from "../utils/appError.js";
import { generateAccessToken, generateRefreshToken } from "../utils/jwt.js";
import jwt from "jsonwebtoken";



// ---------------------- admin login -------------------------------
export const adminLogin = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return next(new AppError("Please provide email and password", 400));
  }

  const admin = await Admin.findOne({ email }).select("+password");
  if (!admin) return next(new AppError("Admin does not exist", 404));

  if (password !== admin.password)
    return next(new AppError("Invalid credentials", 401));

  const accessToken = generateAccessToken(admin._id);
  const refreshToken = generateRefreshToken(admin._id);

  const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "Lax",
  };

  res.cookie("admin-access-token", accessToken, {
    ...cookieOptions,
    expires: new Date(Date.now() + 2 * 60 * 1000),
  });
  res.cookie("admin-refresh-token", refreshToken, {
    ...cookieOptions,
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
  });

  return res.status(200).json({
    status: "success",
    message: "Admin login successful",
    accessToken,
    refreshToken,
    admin: {
      id: admin._id,
      username: admin.username,
      email: admin.email,
    },
  });
});


// ------------------ admin Logout -------------------
export const adminLogout = catchAsync(async (req, res, next) => {
  res.clearCookie("admin-access-token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "Lax",
  });

  res.clearCookie("admin-refresh-token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "Lax",
  });

  return res.status(200).json({
    status: "success",
    message: "Logout successful",
  });
});


// --------------- refresh the admin access token ----------------
export const refreshAdminAccessToken = catchAsync(async (req, res, next) => {
  const refreshToken = req.cookies["admin-refresh-token"];
  if (!refreshToken) return next(new AppError("Refresh token is missing", 401));

  try {
    const decoded = jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_TOKEN_SECRET_KEY
    );

    const admin = await Admin.findById(decoded.id).select("-password");
    if (!admin) return next(new AppError("Admin not found", 401));

    const newAccessToken = generateAccessToken(admin._id);

    const cookieOptions = {
      expires: new Date(Date.now() + 2 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "Lax",
    };

    res.cookie("admin-access-token", newAccessToken, cookieOptions);

    return res.status(200).json({
      status: "success",
      message: "Access token refreshed successfully",
      accessToken: newAccessToken,
    });
  } catch (err) {
    console.error("Token Verification Error: ", err);
    return next(new AppError("Refresh token is invalid or has expired", 403));
  }
});


//------------------- list all users ----------------------
export const getAllUsers = catchAsync(async (req, res, next) => {
  const users = await User.find();
  if (!users || users.length === 0) {
    return next(new AppError("No Users Founded", 404));
  }
  return res.status(200).json({
    status: "success",
    message: "Successfully Listed User Data ",
    data: { users },
  });
});
