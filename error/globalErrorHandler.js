// const globalErrorHandler = (err, req, res, next) => {
//     err.statusCode = err.statusCode || 500;
//     err.status = err.status || 'error';
  
//     res.status(err.statusCode).json({
//         status: err.status,
//         error : err,
//         message : err.message,
//         message : err.stack,
//         // stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
//     });
//   };



const globalErrorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';
  // Prepare the response object
  const response = {
      status: err.status,
      message: err.message || 'Something went wrong!', // Use a default message if none is provided
  };
  // Include stack trace only in development mode
  if (process.env.NODE_ENV === 'development') {
      response.stack = err.stack;
  }
  res.status(err.statusCode).json(response);
}


export default globalErrorHandler;