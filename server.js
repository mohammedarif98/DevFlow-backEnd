import app from "./app.js";
import dotenv from "dotenv";
import connectDB from "./config/db.js";

dotenv.config();      // Load environment variables from .env file
connectDB()           // Connect to the database 



const PORT = process.env.PORT || 5000
    
app.listen(PORT,()=>{ 
    console.log(`Server is running on port ${PORT}`);
});