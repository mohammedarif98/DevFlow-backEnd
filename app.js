import session from "express-session";
import express from "express";
import cookieParser  from "cookie-parser";
import cors from "cors";
import logger from "morgan";
import authRouter from "./routes/authRoutes.js";
import adminRouter from "./routes/adminRoutes.js"
import globalErrorHandler from "./error/globalErrorHandler.js";
import AppError from "./utils/appError.js";


const app = express();

app.use(cors({
    origin: "http://localhost:5173",
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    credentials: true,
}));


// Configure session middleware store email
app.use(session({
    secret: process.env.SESSION_SECRET_KEY, 
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
}));


app.use(cookieParser());
app.use(express.json({limit: "10mb"}));        //------- Middleware to parse JSON requests with a limit ----- ---
app.use(express.urlencoded({ extended: true }));
app.use(logger('dev'));


app.use("/api/auth", authRouter);
app.use("/api/admin", adminRouter);

// Handle all undefined routes
app.all('*', (req, res, next) => {
    next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});


// global error handler middleware 
app.use(globalErrorHandler);


export default app; 