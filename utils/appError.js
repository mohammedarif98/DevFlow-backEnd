import globalErrorHandler from "../error/globalErrorHandler.js";


// class AppError extends Error {
//     constructor(message, statusCode) {
//       super(message);
//       this.statusCode = statusCode;
//       this.status = `${statusCode}`.startsWith("4") ? "fail" : "error";
//       this.isOperational = true;  
//       Error.captureStackTrace(this, this.constructor);
//     }
//   }


function AppError(message, statusCode) {
    const error = new Error(message);  // Create an error object with the message
    
    error.statusCode = statusCode;
    error.status = `${statusCode}`.startsWith("4") ? "fail" : "error";
    // error.status = statusCode >= 400 && statusCode < 500 ? "fail" : "error";
    error.isOperational = true;
  
    Error.captureStackTrace(error, globalErrorHandler);
  
    return error;  
  }
  

  export default AppError;