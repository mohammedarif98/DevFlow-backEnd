import crypto from 'crypto';


export function generateOTP() {
    return crypto.randomInt(1000, 10000).toString();
}

