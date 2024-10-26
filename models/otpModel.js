import mongoose from "mongoose";


const otpSchema = new mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true 
    }, 
    otp: {
        type: String,
        default: null
    },
    otpExpires: {
        type: Date,
        default: null
    },
    resetPasswordOTP: {
        type: String,
        default: null
    },
    resetPasswordOTPExpires: {
        type: Date,
        default: null
    },
},
{ timestamps: true }
);



// Index to automatically delete expired OTPs
otpSchema.index({ otpExpires: 1 }, { expireAfterSeconds: 0 });
otpSchema.index({ resetPasswordOTPExpires: 1 }, { expireAfterSeconds: 0 });


const OTP = mongoose.model("OTP", otpSchema);

export default OTP;
