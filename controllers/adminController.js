import { catchAsync } from "../error/catchAsync.js";
import Admin from "../models/adminModel.js";
import Category from "../models/categoryModel.js";
import User from "../models/userModel.js";
import AppError from "../utils/appError.js";
import { uploadCloud } from "../utils/cloudinary.js";
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
    expires: new Date(Date.now() + 15 * 60 * 1000),
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
      expires: new Date(Date.now() + 15 * 60 * 1000),
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
  const users = await User.find({ isVerified: true });
  if (!users || users.length === 0) {
    return next(new AppError("No Users Founded", 404));
  }
  return res.status(200).json({
    status: "success",
    message: "Successfully Listed User Data ",
    data: { users },
  });
});


//------------------- blocking the users ----------------------
export const blockUser = catchAsync(async( req, res, next) => {
  const { userId } = req.params;
  const user = await User.findById(userId);
  if(!user){
    return next(new AppError("User Not Found",404));
  }
  if(!user.isVerified){
    return next(new AppError('User is not verified',403));
  }
  user.isBlocked = true;
  await user.save(); 
  
  return res.status(200).json({ status: "success", message: "User blocked successfully"});
});


//------------------- unblocking the users ----------------------
export const unblockUser = catchAsync(async( req, res, next) => {
  const { userId } = req.params;
  const user = await User.findById(userId);
  if(!user){
    return next(new AppError("User Not Found",404));
  }
  if(!user.isVerified){
    return next(new AppError('User is not verified',403));
  }
  user.isBlocked = false;
  await user.save();

  return res.status(200).json({ status: "success", message: "User unblocked successfully"});
});


// -------------- adding category -----------------
export const addCategory = catchAsync(async( req, res, next) => {
  const { categoryName, description } = req.body;

  if (!categoryName || !description) {
    return next(new AppError("Category name is required", 400));
  }

  const existedCategory = await Category.findOne({categoryName: categoryName});

  if(existedCategory){
    return next(new AppError("Category already exist",400));
  }

  if (!req.file) {
    return next(new AppError("Category image is required", 400));
  }

  const uploadedImageUrl = await uploadCloud(req.file.buffer, req.file.originalname, 'category');
  if (!uploadedImageUrl) {
    return next(new AppError("Failed to upload image", 500));
  }

  const newCategory = new Category({
    categoryName,
    categoryImage: uploadedImageUrl,
    description,
  });

  await newCategory.save();

  return res.status(201).json({
    status: 'success',
    message: "Category added successfully.",
    category: newCategory,
  });

});


// -------------- get all category ----------------
export const getCategory = catchAsync(async(req, res, next) => {
  const category = await Category.find();
  if(!category){
    return next(new AppError("Category is not found",404));
  }
  return res.status(200).json({
    status: "success",
    message: "Category fetched uccessfully",
    data: { category }
  })
})


// --------------- category edit function ----------------
export const editCategory = catchAsync(async (req, res, next) => {
  const { categoryId } = req.params;
  const { categoryName, description } = req.body;

  if (!categoryId) {
    return next(new AppError("Category ID is required", 400));
  }

  const category = await Category.findById(categoryId);
  if (!category) {
    return next(new AppError("Category not found", 404));
  }

  if (categoryName) {
    const existedCategory = await Category.findOne({ categoryName: categoryName.trim() });
    if (existedCategory && existedCategory._id.toString() !== categoryId) {
      return next(new AppError("Category name already exists", 400));
    }
    category.categoryName = categoryName.trim();
  }

  if (description) {
    category.description = description;
  }

  if (req.file) {
    const uploadedImageUrl = await uploadCloud(req.file.buffer, req.file.originalname, 'category');
    if (!uploadedImageUrl) {
      return next(new AppError("Failed to upload image", 500));
    }
    category.categoryImage = uploadedImageUrl;
  }

  await category.save();

  return res.status(200).json({
    status: 'success',
    message: "Category updated successfully.",
    category: category,
  });
});