import mongoose from "mongoose";


const blogSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true
    },
    content: {
        type: String,
        required: true
    },
    tags: [{ type: String }],
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true 
    },
    category: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Category'
    },
    coverImage: {
        type: String,
        default: ''
    },
    isPublished: {
        type: Boolean,
        default: true
    },
    publishedAt: {
        type: Date
    },
},{ timestamps: true }
);


const Blog = mongoose.model("Blog",blogSchema);
export default Blog;