import mongoose from "mongoose";


const categorySchema = new mongoose.Schema({
    categoryName: {
        type: String,
        required: true,
    },
    categoryImage: {
        type: String,
    },
    description: {
        type: String,
        required: true,
    },
    isListed: {
        type: Boolean,
        default: true
    }
},{ timestamps: true }
);


const Category = mongoose.model("Category",categorySchema);
export default Category;