import mongoose from "mongoose";


const commentSchema = new mongoose.Schema({
    content: {
        type: String,
        required: true, 
        trim: true
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    blog: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Blog',
        required: true
    },
    replies: [{
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true
        },
        content: {
            type: String,
            required: true,
            trim: true,
        },
        createdAt: {
            type: Date,
            default: Date.now,
        },
    }],
    isDeleted: {
        type: Boolean,
        default: false, 
    }
},
{ timestamps: true });



// Indexes for efficient querying
commentSchema.index({ user: 1 });
commentSchema.index({ blog: 1 });
commentSchema.index({ replies: 1 });

const Comment = mongoose.model('Comment', commentSchema);
export default Comment;