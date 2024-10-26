import jwt from "jsonwebtoken";



const generateAccessToken = (id) => {
    return jwt.sign({ id}, process.env.JWT_ACCESS_TOKEN_SECRET_KEY, {
        expiresIn: process.env.JWT_ACCESS_TOKEN_EXPIRES_IN,
    });
};



const generateRefreshToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_REFRESH_TOKEN_SECRET_KEY, {
        expiresIn: process.env.JWT_REFRESH_TOKEN_EXPIRES_IN,
    });
};


export { generateAccessToken, generateRefreshToken }