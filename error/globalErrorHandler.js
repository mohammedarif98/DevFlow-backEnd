

const globalErrorHandler = (err, req, res, next) => {
    err.statusCode = err.statusCode || 500;
    err.status = err.status || 'error';
  
    res.status(err.statusCode).json({
        status: err.status,
        error : err,
        message : err.message,
        message : err.stack,
        // stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
  };



export default globalErrorHandler;