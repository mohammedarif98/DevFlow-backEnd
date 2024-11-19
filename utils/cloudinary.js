import { v2 as cloudinary } from "cloudinary";
import dotenv from "dotenv";
dotenv.config();


export default cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_SECRET_KEY,
});


export const uploadCloud = async (buffer, filename, purpose) => {
  try {
    const folders = {
        profile: "profile",
        category: "category",
        blog: "blog",
    };

    const folder = folders[purpose] || "general-uploads"; 

    const mimeTypes = {
      jpg: "image/jpeg",
      jpeg: "image/jpeg",
      webp: "image/webp",
      png: "image/png",
      gif: "image/gif",
      mp4: "video/mp4",
    };

    if (!filename) {
        throw new Error("Filename is undefined");
    }

    const ext = filename.split(".").pop().toLowerCase();
    const mimeType = mimeTypes[ext];
    if (!mimeType) throw new Error("Unsupported file format");

    const base64String = buffer.toString("base64");
    const sanitizedFilename = filename.replace(/[\W_]+/g, "_");

    // --------- Upload to Cloudinary ----------
    const result = await cloudinary.uploader.upload(
        `data:${mimeType};base64,${base64String}`,
        {
          folder, 
          public_id: sanitizedFilename,
          resource_type: "auto", 
        }
    );

    return result.secure_url;
  } catch (error) {
    console.error("Error uploading to Cloudinary:", error);
    return null;
  }
};
