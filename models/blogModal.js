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
    coverImage: {
        type: String,
        default: ''
    },
    tags: {
        type: [String], 
        default: []
    },
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true 
    },
    category: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Category'
    },
    likes: {
        type: [mongoose.Schema.Types.ObjectId],
        ref: 'User',
        default: []
    },
    isPublished: {
        type: Boolean,
        default: true
    },
    publishedAt: {
        type: Date,
        default: Date.now,
        get: (date) => {
            if (!date) return null;
            const options = { month: 'short', day: '2-digit' };
            return new Intl.DateTimeFormat('en-US', options).format(date);
        },
    },
},{
    toJSON: { getters: true }, 
    toObject: { getters: true },
    timestamps: true,
}
);


const Blog = mongoose.model("Blog",blogSchema);
export default Blog;