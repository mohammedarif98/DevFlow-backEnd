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
    profilePhoto: {
        type: String,
        required: false,
        default: '',
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        trim: true,
        select: false
    },
    isVerified: {
        type: Boolean,
        default: false
    },   
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