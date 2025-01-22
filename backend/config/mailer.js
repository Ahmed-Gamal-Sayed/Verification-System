import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();


const transport = nodemailer.createTransport({
    host: process.env.MAILTRAP_HOST,
    port: process.env.MAILTRAP_PORT,
    auth: {
        user: process.env.MAILTRAP_USER,
        pass: process.env.MAILTRAP_PASS
    }
});

const sendEmail = async () => {
    try {
        const info = await transport.sendMail({
            from: '"Test Sender" <test@example.com>', // Sender address
            to: 'recipient@example.com', // Receiver address
            subject: 'Verify Email', // Email subject
            text: 'Hello, this is a test email from Mailtrap!', // Plain text body
            html: '<b>Hello, this is a test email from Mailtrap!</b>', // HTML body
        });

        console.log('Email sent:', info.messageId);
    } catch (error) {
        console.error('Error sending email:', error.message);
    }
};
