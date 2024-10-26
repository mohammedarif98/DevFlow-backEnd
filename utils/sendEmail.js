import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();         // Load environment variables from .env file




// Create a transporter using nodemailer
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_ID,
        pass: process.env.EMAIL_PASSWORD, 
    },
});

//// Optional: Test the transporter
// transporter.verify((error, success) => {
//     if (error) { 
//         console.error('Transporter verification error:', error);
//     } else {
//         console.log('Transporter is ready to send emails');
//     }
// });




// Function to send email
const sendMail = async (to, subject, html) => {
    const mailOptions = {
        from: `"devFlow" <${process.env.EMAIL_ID}>`,  // Use environment variable for sender email
        to,
        subject,
        html,
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`Email sent to ${to}: ${subject}`);
    } catch (error) {
        console.error(`Error sending email to ${to}:`, error.message);
        throw new Error(`Failed to send email: ${error.message}`);
    }
};




export default sendMail;
