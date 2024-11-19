import multer from 'multer';

const storage = multer.memoryStorage();

export const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
      cb(null, true);  // Accept the file
    } else {
      cb(new Error('File type not supported!'), false);  // Reject the file
    }
};


// Set up Multer middleware with options
export const upload = multer({
    storage: storage,
    fileFilter: fileFilter, 
    // limits: { fileSize: 10 * 1024 * 1024 },
});
  

