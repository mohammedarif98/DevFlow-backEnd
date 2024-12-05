import { catchAsync } from "../error/catchAsync.js";
import User from "../models/userModel.js";
import OTP from "../models/otpModel.js";
import AppError from "../utils/appError.js";
import { generateOTP } from "../utils/generateOTP.js";
import sendMail from "../utils/sendEmail.js";
import { generateAccessToken, generateRefreshToken } from "../utils/jwt.js";
import comparePassword from "../utils/comparePassword.js";
import jwt from "jsonwebtoken";
import bcryptjs from "bcryptjs";
import { uploadCloud } from "../utils/cloudinary.js";
import Blog from "../models/blogModal.js";
import Category from "../models/categoryModel.js";
import mongoose from "mongoose";
import Comment from "../models/commentModel.js";

// --------------- User Registration ----------------
export const registerUser = catchAsync(async (req, res, next) => {
  const { username, email, password, confirmPassword } = req.body;

  if (!username || !email || !password || !confirmPassword)
    return next(new AppError("Fill all fields", 400));
  if (password !== confirmPassword)
    return next(new AppError("Passwords do not match", 400));

  const existUser = await User.findOne({ email });
  if (existUser) return next(new AppError("User is already exist", 400));

  const otp = generateOTP();
  const otpExpires = Date.now() + 5 * 60 * 1000; // otp expires after 5 min

  const user = new User({
    username,
    email,
    password,
    confirmPassword,
  });
  await user.save();

  await OTP.create({
    userId: user._id,
    otp,
    otpExpires,
  });

  await sendMail(
    email,
    "OTP For Email Verification",
    `<h1>Your OTP is: ${otp}</h1>`
  );

  // Store the email in the session
  req.session.email = email;

  return res.status(201).json({
    status: "success",
    message: "User registered. OTP sent to Email",
  });
});

// ---------------- email OTP Verification --------------------
export const verifyOTP = catchAsync(async (req, res, next) => {
  const { otp } = req.body;

  if (!otp) return next(new AppError("OTP is required! please fill OTP", 400));

  const findOTP = await OTP.findOne({ otp, otpExpires: { $gt: Date.now() } });

  if (!findOTP) return next(new AppError("Invalid or expired OTP", 400));

  const user = await User.findById(findOTP.userId);
  if (!user) return next(new AppError("User not found.", 404));

  user.isVerified = true;
  await user.save({ validateBeforeSave: false });

  // Clear the OTP data from the database after successful verification
  await OTP.findByIdAndDelete(findOTP._id);

  res.status(200).json({
    status: "success",
    message: "Successfully Verified Account",
  });
});

// ------------------ Resend email OTP -----------------
export const resendOTP = catchAsync(async (req, res, next) => {
  const email = req.session.email;

  if (!email) return next(new AppError("Email is required!", 400));

  const user = await User.findOne({ email });
  if (!user) return next(new AppError("User not found.", 404));

  const existingOTP = await OTP.findOne({ userId: user._id });
  if (existingOTP && existingOTP.otpExpires > Date.now()) {
    return next(
      new AppError(
        "OTP has not yet expired. Please check your email for current OTP",
        400
      )
    );
  }

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

  await sendMail(
    email,
    "New OTP for Email Verification",
    `<h1>Your new OTP is: ${otp}</h1>`
  );

  res.status(200).json({
    status: "success",
    message: "New OTP has been sent to your email.",
  });
});

// ------------------ User Login -------------------
export const loginUser = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password)
    return next(new AppError("Please provide email and password", 400));

  const user = await User.findOne({ email }).select("+password");
  if (!user) return next(new AppError("User does not exist", 404));

  if (!user.isVerified)
    return next(
      new AppError("Your email has not been verified. Verify email.", 400)
    );

  if (user.isBlocked)
    return next(
      new AppError(
        "Your account has been blocked by admin. Please contact admin",
        403
      )
    );

  const isPasswordCorrect = await comparePassword(password, user.password);
  if (!isPasswordCorrect) return next(new AppError("Invalid credentials", 401));

  const accessToken = generateAccessToken(user._id);
  const refreshToken = generateRefreshToken(user._id);

  const accessTokenCookieOptions = {
    expires: new Date(Date.now() + 15 * 60 * 1000),
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "Lax",
  };

  const refreshTokenCookieOptions = {
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "Lax",
  };

  res.cookie("user-access-token", accessToken, accessTokenCookieOptions);
  res.cookie("user-refresh-token", refreshToken, refreshTokenCookieOptions);

  const { password: userpassword, ...rest } = user.toObject();

  return res.status(200).json({
    status: "success",
    message: "Login successfull",
    accessToken,
    refreshToken,
    user: rest,
  });
});

// --------------- Google authentication -------------------
export const googleAuth = catchAsync(async (req, res, next) => {
  const { email, name, photo } = req.body;

  let user = await User.findOne({ email });
  if (!user) {
    const generatedPassword =
      Math.random().toString(36).slice(-8) +
      Math.random().toString(36).slice(-8);
    console.log("Generated Password:", generatedPassword);
    const hashedPassword = bcryptjs.hashSync(generatedPassword, 10);
    console.log("Hashed Password:", hashedPassword);

    user = new User({
      username: name,
      email: email,
      profilePhoto: photo,
      password: hashedPassword,
      isVerified: true,
    });
    user.confirmPassword = hashedPassword;
    await user.save();
  }

  const accessToken = generateAccessToken(user._id);
  const refreshToken = generateRefreshToken(user._id);

  const accessTokenCookieOptions = {
    expires: new Date(Date.now() + 15 * 60 * 1000),
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "Lax",
  };

  const refreshTokenCookieOptions = {
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "Lax",
  };

  res.cookie("user-access-token", accessToken, accessTokenCookieOptions);
  res.cookie("user-refresh-token", refreshToken, refreshTokenCookieOptions);

  const { password, ...rest } = user.toObject();

  return res.status(200).json({
    status: "success",
    message: "Google authentication successful",
    accessToken,
    refreshToken,
    user: rest,
  });
});

// ------------------ User Logout -------------------
export const logoutUser = catchAsync(async (req, res, next) => {
  res.clearCookie("user-access-token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "Lax",
  });

  res.clearCookie("user-refresh-token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "Lax",
  });

  return res.status(200).json({
    status: "success",
    message: "Logout successful",
  });
});

// ------------------ refresh the user access token -------------------
export const refreshAccessToken = catchAsync(async (req, res, next) => {
  const refreshToken = req.cookies["user-refresh-token"];
  if (!refreshToken) return next(new AppError("Refresh token is missing", 401));

  try {
    const decoded = jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_TOKEN_SECRET_KEY
    );

    const user = await User.findById(decoded.id).select("-password");
    if (!user) return next(new AppError("User not found", 401));

    const newAccessToken = generateAccessToken(user._id);

    const cookieOptions = {
      expires: new Date(Date.now() + 15 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "Lax",
    };

    res.cookie("user-access-token", newAccessToken, cookieOptions);

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

// --------------------- user profile ----------------------
export const getUserProfile = catchAsync(async (req, res, next) => {
  const userId = req.user.id;
  const user = await User.findById(userId).select("-password");
  if (!user) {
    return next(new AppError("User Not Found", 404));
  }

  const { password, ...rest } = user.toObject();

  res.status(200).json({
    status: "success",
    message: "User Profile Fetched Successfully",
    user: rest,
  });
});

// ---------------- update user profile datails --------------------
export const updateUserProfile = catchAsync(async (req, res, next) => {
  const { username } = req.body;
  const userId = req.user.id;
  console.log(userId);

  const user = await User.findById(userId);
  if (!user) return next(new AppError("User not found", 404));

  let imageUrl = user.profilePhoto;

  if (req.file) {
    const filename = req.file.originalname;
    if (!filename) return next(new AppError("File name is undefined", 400));
    imageUrl = await uploadCloud(req.file.buffer, filename, "profile");
    if (!imageUrl)
      return next(new AppError("Failed to upload profile photo"), 500);
  }

  const updatedUser = await User.findByIdAndUpdate(
    userId,
    {
      username,
      profilePhoto: imageUrl,
    },
    { new: true }
  );

  if (!updatedUser)
    return next(new AppError("Failed to update user profile", 500));
  const { password, ...rest } = updatedUser.toObject();

  return res.status(200).json({
    message: "Updated Successfully",
    user: rest,
  });
});

// -------------- get all category ----------------
export const getAllCategory = catchAsync(async (req, res, next) => {
  const category = await Category.find();
  if (!category) {
    return next(new AppError("Category is not found", 404));
  }
  return res.status(200).json({
    status: "success",
    message: "Category fetched uccessfully",
    data: category
  });
});


//-------------- get all user --------------------
export const getAllUser = catchAsync(async (req, res, next) => {
  const currentUserId = req.user._id; 
  const users = await User.find({ _id: { $ne: currentUserId }, isVerified: true, isBlocked: false });
  if(!users || users.length === 0){
    return next(new AppError("User not found", 404))
  }
  return res.status(200).json({
    status: "success",
    message: "Users fetched uccessfully",
    data: users
  });
});


// ---------------- Add blog post--------------------
export const createBlogPost = catchAsync(async (req, res, next) => {
  const { title, content, tags, category } = req.body;
  const author = req.user._id;

  if (!title || !content) {
    return next(new AppError("Title and content are required", 400));
  }

  let coverImageUrl = "";
  if (req.file) {
    coverImageUrl = await uploadCloud(
      req.file.buffer,
      req.file.originalname,
      "blog"
    );
    if (!coverImageUrl) {
      return next(new AppError("Failed to upload image", 500));
    }
  }

  let tagsArray = [];
  try {
    tagsArray = JSON.parse(tags || "[]"); // Parse JSON string to array
  } catch (e) {
    console.error("Error parsing tags:", e);
    tagsArray = [];
  }

  const newBlogPost = new Blog({
    title: title.trim(),
    content: content,
    author: author,
    tags: tagsArray,
    category: category || null,
    coverImage: coverImageUrl,
    publishedAt: new Date(),
  });

  await newBlogPost.save();

  return res.status(201).json({
    status: "success",
    message: "created Successfully",
    blogPost: newBlogPost,
  });
});

// ---------------- Edit blog post --------------------
export const editBlogPost = catchAsync(async (req, res, next) => {
  const { title, content, tags, category } = req.body;
  const { blogId } = req.params;
  const userId = req.user._id;
  let updatedCoverImageUrl = null;

  if (!blogId) {
    return next(new AppError("Blog ID is required", 400));
  }

  const blogPost = await Blog.findById(blogId);
  if (!blogPost) {
    return next(new AppError("Blog post not found", 404));
  }

  if (blogPost.author.toString() !== userId.toString()) {
    return next(
      new AppError("You are not authorized to edit this blog post", 403)
    );
  }

  let tagsArray = [];
  try {
    tagsArray = JSON.parse(tags || "[]");
  } catch (e) {
    console.error("Error parsing tags:", e);
    tagsArray = [];
  }

  if (req.file) {
    updatedCoverImageUrl = await uploadCloud(
      req.file.buffer,
      req.file.originalname,
      "blog"
    );
    if (!updatedCoverImageUrl) {
      return next(new AppError("Failed to upload image", 500));
    }
  }

  if (title) blogPost.title = title.trim();
  if (content) blogPost.content = content;
  if (tags) blogPost.tags = tagsArray;
  if (category !== undefined) {
    if (category === null) {
      blogPost.category = null;
    } else {
      const isValidObjectId = mongoose.Types.ObjectId.isValid(category);
      if (!isValidObjectId) {
        return next(new AppError("Invalid category ID", 400));
      }
      const existingCategory = await Category.findById(category);
      if (!existingCategory) {
        return next(new AppError("Category not found", 404));
      }
      blogPost.category = category;
    }
  }
  if (updatedCoverImageUrl) blogPost.coverImage = updatedCoverImageUrl;

  await blogPost.save();

  return res.status(200).json({
    status: "success",
    message: "Blog updated successfully.",
    blogPost,
  });
});


// ---------------- get all blog --------------------
export const getAllBlogs = catchAsync(async (req, res, next) => {

  const blogs = await Blog.find({ isPublished: true })
    .populate("author").populate('comments')
    .sort({ createdAt: -1 });

  if (!blogs) return next(new AppError("Blogs is not found", 404));
  
  return res.status(200).json({
    status: "success",
    message: "Blogs fetched successfully",
    data: { blogs },
  });
});


//----------------- get the details of selected blogs --------------------
export const getBlogDetail = catchAsync(async (req, res, next) => {
  const { blogId } = req.params;
  const blog = await Blog.findById(blogId)
    .populate("author")
    .populate("category");
  if (!blog) {
    return next(new AppError("Not found the blog", 404));
  }
  res.status(200).json({
    status: "success",
    message: "Blog fetched successfully",
    data: blog,
  });
});

//------------------ fetch the uploaded own blogs of user --------------------
export const getUserBlogs = catchAsync(async (req, res, next) => {
  const userId = req.user.id;
  if (!userId) {
    return next(new AppError("User not found. Please logIn.", 401));
  }
  const blogs = await Blog.find({ author: userId }).sort({ createdAt: -1 });
  res.status(200).json({
    status: "success",
    message: "Blogs Fetched Successfully",
    data: blogs,
  });
});

// ------------------ like blog  ----------------------
export const likeBlog = catchAsync(async(req, res, next) => {
  const {blogId} = req.params;
  const userId = req.user._id;

  const blog = await Blog.findByIdAndUpdate(
    blogId,
    { $addToSet: {likes: userId} },
    {new: true}
  ); 

  if (!blog) return next(new AppError("Blog not found",404));
  
  res.status(200).json({
    status: "success",
    message: "liked Successfully",
    data: blog.likes.length
  })
})

// ------------------ unlike blog  ---------------------
export const UnlikeBlog = catchAsync(async(req, res, next) => {
  const {blogId} = req.params;
  const userId = req.user._id;
  
  const blog = await Blog.findByIdAndUpdate(
    blogId,
    {$pull: {likes: userId}},
    {new: true}
  );
  
  if (!blog) return next(new AppError("Blog not found",404));
  
  res.status(200).json({
    status: "success",
    message: "unliked Successfully",
    data: blog.likes.length
  })
});

// ------------------ total like count of blog  ---------------------
export const getBlogLikeCount = catchAsync(async(req, res, next) => {
  const { blogId } = req.params;
  const blog = await Blog.findById(blogId);
  if (!blog) {
    return next(new AppError('Blog not found', 404));
  }
  const likeCount = blog.likes.length();
  res.status(200).json({
    status: "success",
    message: "Total like fetched",
    data: {likeCount}
  })
})


//------------------ add blog to bookmark  ------------------
export const bookmarkBlog = catchAsync(async(req, res, next) => {
  const { blogId } = req.params;
  const userId = req.user._id;
  
  const blog = await Blog.findById(blogId);
  if (!blog) {
    return next(new AppError('Blog not found', 404));
  }

  const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $addToSet: { bookmarks: blogId } }, 
      { new: true } 
  );

  res.status(200).json({
    status: "success",
    message: "blog bookmarked successfully",
    data: updatedUser.bookmarks
  })
});


//------------------ remove blogs from bookmark ------------------
export const unbookmarkBlog = catchAsync(async(req, res, next) => {
  const { blogId } = req.params;
  const userId = req.user._id;

  const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $pull: { bookmarks: blogId } }, 
      { new: true }
  );

  if(!updatedUser) return res.status(404).json({ message: "User not found" });
    
  res.status(200).json({
    status: "success",
    message: "blog unbookmarked successfully",
    data: updatedUser.bookmarks
  })
});


//---------------- add comments to blog -------------------
export const addComment  = catchAsync(async(req, res, next) => {
  const { blogId } = req.params;
  const userId = req.user._id;
  const { content } = req.body;

  if (!content || content.trim() === '') {
    return next( new AppError('Comment content is required.', 400));
  }
  
  const blog = await Blog.findById(blogId);
  if(!blog) return next(new AppError("Blog not found", 404)); 

  const comment = new Comment({
    content,
    user: userId,
    blog: blogId,
  });

  await comment.save();

  res.status(200).json({
    status: 'success',
    message: 'Comment added successfully',
    data: comment
  });
})


//----------------get the comments of own blog post -------------------
export const getComments = catchAsync(async(req, res, next) => {
  const { blogId } = req.params;

  const comments = await Comment.find({
      blog: blogId, 
      isDeleted: false 
    }).
      populate('user').
      populate('replies').
      sort({createdAt: -1});

  if (!comments) return next(new AppError("No comments found for this blog", 404));

  res.status(200).json({
    status: 'success',
    message: 'Comment fetched successfully',
    results: comments.length,
    data: { comments }
  });
})


//---------------- give replies on already added comments of blog post -------------------
export const repliesToComments = catchAsync(async(req, res, next) => {
  const { blogId, commentId } = req.params;
  const { replyContent } = req.body;
  const userId = req.user._id;

  if (!mongoose.Types.ObjectId.isValid(blogId)) return next(new AppError("Invalid blog ID format", 400));
  if (!mongoose.Types.ObjectId.isValid(commentId)) return next(new AppError("Invalid comment ID format", 400));

  const comment = await Comment.findById(commentId).populate('user').populate('replies.user');
  if (!comment) return next(new AppError("Comment not found", 404));

  const reply = {
    user: userId,
    replyContent,
    createdAt: Date.now(),
  };

  comment.replies.push(reply);
  await comment.save();
  await comment.populate('replies');

  res.status(201).json({
    status: 'success',
    message: 'Reply added successfully',
    data: comment 
  });
});


//----------------delete the comments of blog posted -------------------
export const deleteComments = catchAsync(async(req, res, next) => {
  const { commentId } = req.params; 
  const userId = req.user._id;

  const comment = await Comment.findById(commentId);

  if (!comment) return next(new AppError('Comment not found', 404));

  if (String(comment.user) !== String(userId)) return next(new AppError('Delete only by commented user', 403));

  comment.isDeleted = true;
  comment.replies = [];       // removing all replies
  await comment.save();

  res.status(200).json({
    status: 'success',
    message: 'Comment and its replies deleted successfully'
  });
});


//----------------delete the comment reply of blog posted -------------------
export const deleteReply = catchAsync(async (req, res, next) => {
  const { commentId, replyId } = req.params;
  const userId = req.user._id;

  if (!mongoose.Types.ObjectId.isValid(commentId)) return next(new AppError('Invalid comment ID', 400));
  if (!mongoose.Types.ObjectId.isValid(replyId)) return next(new AppError('Invalid reply ID', 400));

  const comment = await Comment.findById(commentId).populate('replies.user');
  if (!comment) return next(new AppError('Comment not found', 404));

  // Find the specific reply by replyId
  const reply = comment.replies.id(replyId); 
  if (!reply) return next(new AppError('Reply not found', 404));

  // Check if the user is the owner of the reply
  if (String(reply.user._id) !== String(userId)) {
    return next(new AppError('Delete only by replied user', 403));
  }

  reply.isReplyDeleted = true;
  await comment.save();

  res.status(200).json({
    status: 'success',
    message: 'Reply of comment deleted successfully'
  });
});


//------------------- follow user ----------------------
export const followUser = catchAsync( async(req, res, next) => {
  const userId = req.user._id;
  const { userIdToFollow } = req.params;

  if (userId.equals(userIdToFollow)) return next(new AppError('You cannot follow yourself', 400));

  // Find user and the user to follow
  const user = await User.findById(userId).select('following');
  const userToFollow = await User.findById(userIdToFollow).select('followers');
  if (!userToFollow) return next(new AppError('User to follow not found', 404));

  // add the user to the following list
  await User.findByIdAndUpdate(userId, {$addToSet: {following: userIdToFollow}});
  // add the user to the followers list of the user being followed
  await User.findByIdAndUpdate(userIdToFollow, {$addToSet: {followers: userId}});

  res.status(200).json({
    status: 'success',
    message: 'You are now following this user',
  });
});


//------------------ unfollow user -----------------------
export const unfollowUser = catchAsync( async(req, res, next) => {
  const userId = req.user._id;
  const { userIdToUnfollow } = req.params;

  // Find user and the user to unfollow
  const user = await User.findById(userId).select('following');
  const userToUnfollow = await User.findById(userIdToUnfollow).select('followers');
  if(!userToUnfollow) return next(new AppError("User to unfollow not found",404));

  // Check user is not following the user
  if (!user.following.includes(userIdToUnfollow)) return next(new AppError('You are not following this user', 400));

  // remove user from the following list
  await User.findByIdAndUpdate(userId, {$pull: {following: userIdToUnfollow}});
  // remove the current user from the followers list of the user being unfollowed
  await User.findByIdAndUpdate(userIdToUnfollow, {$pull: {followers: userId}});
  
  res.status(200).json({
    status: 'success',
    message: 'You are now unfollowed this user',
  });
});


//----------------------- follow the category by user --------------------------
export const followCategory = catchAsync( async(req, res, next) => {
  const userId = req.user._id;
  const { categoryId } = req.params;

  if (!mongoose.Types.ObjectId.isValid(categoryId)) return next(new AppError('Invalid category ID.', 400));

  const user = await User.findByIdAndUpdate(
    userId,
    { $addToSet :{ followedCategory: categoryId } },
    { new: true }
  );

  if(!user) return next(new AppError("user not found",404));

  res.status(200).json({
    status: 'success',
    message: "catetgory follow successfully",
    data: user
  });
});


//----------------------- unfollow the category by user ------------------------
export const unfollowCategory = catchAsync( async(req, res, next) => {
  const userId = req.user._id;
  const { categoryId } = req.params;

  if (!mongoose.Types.ObjectId.isValid(categoryId)) return next(new AppError('Invalid category ID.', 400));

  const user = await User.findByIdAndUpdate(
    userId,
    {$pull :{ followedCategory: categoryId }},
    {new : true}
  );

  if(!user) return next(new AppError("user not found",404));


  res.status(200).json({
    status: 'success',
    message: "catetgory is unfollow successfully",
    data: user
  });
});


//------------------- get the details of followed user   ------------------------
export const getFollowedUsers = catchAsync( async(req, res, next) => {
  const userId = req.user._id;
  // Find the logged-in user and populate the 'following' array with user details
  const user = await User.findById(userId).populate('following');
  if (!user) return next(new AppError('User not found', 404));

  res.status(200).json({
    status: 'success',
    message: "successfully ger followedusers",
    data: {
      followedUsers: user.following,
    },
  });
});


//--------------------------------------------------
export const getUsersPage = catchAsync( async(req, res, next) => {
  const userId = req.user._id;
  const { usersId } = req.params;    // to get thw id of blog posted users

  if (!userId) {
    return next(new AppError('You are not logged in. Please log in to access this resource.', 401));
  }

  const user = await User.findById(usersId);
  if (!user) return next(new AppError('User not found', 404));

  const blogs = await Blog.find({
    author: usersId 
  })
    .populate('category')
    .populate({
      path: 'author',
      populate: ['following', 'followers'],       // Populate followers and following of author
    }).sort({ createdAt: -1 });

  res.status(200).json({
    status: 'success',
    message: "users details get successfully",
    data: blogs 
  });
}); 


//--------------------------------------------------
export const getCategoryPage = catchAsync( async(req, res, next) => {
  const userId = req.user._id;
  const categoryId = req.params;
  console.log(categoryId);

  if (!userId) {
    return next(new AppError('You are not logged in. Please log in to access this resource.', 401));
  }

  const category = await Category.findById(categoryId);
  if (!category) return next(new AppError('Caategory id not found', 404));

  const categories= await Blog.find({
    category: categoryId
  })
  .populate('category');

  res.status(200).json({
    status: 'success',
    message: "categies listed successfully",
    data: categories
  });
}); 
