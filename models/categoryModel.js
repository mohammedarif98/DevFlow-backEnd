import mongoose from "mongoose";


const categorySchema = new mongoose.Schema({
    categoryName: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    categoryImage: {
        type: String,
    },
    description: {
        type: String,
        trim: true, 
    },
},{ timestamps: true }
);


const Category = mongoose.model("Category",categorySchema);
export default Category;