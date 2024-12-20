import mongoose from "mongoose";
import bcrypt from "bcryptjs"

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is required'],
        trim: true,
        index: true
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        trim: true,
        unique: true,
        lowercase: true
    },
    role: {
      type: String,
      enum: ["user","author"],
      default: "user",  
    },
    profilePhoto: {
        type: String,
        default: 'https://uxwing.com/wp-content/themes/uxwing/download/peoples-avatars/man-user-circle-icon.svg',
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        trim: true,
        select: false
    },
    bookmarks: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "Blog", 
    }],
    following: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
    }],
    followers: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
    }],
    followedCategory: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "Category"
    }],
    isVerified: {
        type: Boolean,
        default: false
    },  
    isBlocked: {
        type: Boolean,
        default: false
    } 
},
{ timestamps: true }
);



// Virtual field for confirmPassword, will not be persisted in DB
userSchema.virtual('confirmPassword')
    .get(function() { return this._confirmPassword })
    .set(function(value) { this._confirmPassword = value });

// Pre-validate: Check if password and confirmPassword match
userSchema.pre('validate', function(next) {
    if (this.isModified('password') && this.password !== this._confirmPassword) {
        return next(new Error('Passwords do not match'));
    }
    next();
});

// Hash password before saving the user
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 12);
    next();
});



const User = mongoose.model("User",userSchema);

export default User;