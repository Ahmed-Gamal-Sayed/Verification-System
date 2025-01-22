import bcrypt from 'bcrypt';
import { insertNewPassword, insertUser, selectUserByEmail } from '../database/db.js';



// global variables
let globalEmail;



export const signin = async (req, res) => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            throw new Error('All fields are required!');
        }

        const user = await selectUserByEmail(email);
        if (user != null) {

            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                res.status(200).json({ success: true, route: '/dashboard' });
            } else {
                res.status(400).json({ success: false, error: 'Password not correct!' })
            }

        } else {
            res.status(400).json({ success: false, error: 'Email Not Exist!' });
        }

    } catch (error) {
        res.status(400).json({ success: false, error: '[ERROR] Sign in not successfull!' });
    }
};

export const signup = async (req, res) => {
    const { fullname, email, password, repassword } = req.body;

    try {
        if (!fullname || !email || !password || !repassword) {
            throw new Error('All fields are required!');
        }

        const user = await selectUserByEmail(email);
        if (user === null) {
            if (password === repassword) {
                const hashedPassword = await bcrypt.hash(password, 10);
            } else {
                res.status(400).json({ success: false, error: 'Password not corrected!' });
            }

            const verifyCode = Math.floor(100000 + Math.random() * 900000).toString();
            const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            let token = '';
            let length;

            while (1) {
                if (length > 50) { break; }
                length = Math.random() % 255;
            }

            for (let i = 0; i < length; i++) {
                const randomIndex = Math.floor(Math.random() * characters.length);
                token += characters[randomIndex];
            }

            const user = {
                fullname: fullname,
                email: email,
                password: hashedPassword,
                token: token,
                verificationCode: verifyCode,
            };

            const result = await insertUser(user);
            if (result) {
                res.status(200).json({ success: true, route: '/signin' });
            } else {
                res.status(400).json({ success: false, error: 'Sign up not account!' })
            }

        } else {
            res.status(400).json({ success: false, error: 'Email Aleady Exist!' });
        }

    } catch (error) {
        res.status(400).json({ success: false, error: '[ERROR] Sign up not successfull!' });
    }
};

export const checkEmail = async (req, res) => {
    const email = req.body;

    try {
        if (!email) {
            throw new Error('All fields are required!');
        }

        const user = await selectUserByEmail(email);
        if (user !== null) {
            globalEmail = email;
            // send message OTP verification code.
            res.status(200).json({ success: true, route: '/verify-email' });
        } else {
            res.status(400).json({ success: true, error: 'Email not found!' });
        }

    } catch (error) {
        res.status(400).json({ success: false, error: '[ERROR] Check email not successfull!' });
    }
};

export const verifyEmail = async (req, res) => {
    const code = req.body;

    try {
        if (!code) {
            throw new Error('All fields are required!');
        }

        const user = await selectUserByEmail(globalEmail);
        if (user !== null) {
            if (code === user.verificationCode) {
                res.status(200).json({ success: true, route: '/verify-email' });
            } else {
                res.status(400).json({ success: false, error: 'Verification Code Not Right' });
            }
        } else {
            res.status(400).json({ success: false, error: 'Email not found!' });
        }

    } catch (error) {
        res.status(400).json({ success: false, error: '[ERROR] Check email not successfull!' });
    }
};

export const changePassword = async (req, res) => {
    const { password, repassword } = req.body;

    try {
        if (!password || !repassword) {
            throw new Error('All fields are required!');
        }

        if (password === repassword) {
            const hashedPassword = await bcrypt.hash(password, 10);
        } else {
            res.status(400).json({ success: false, error: 'Password not corrected!' });
        }

        if (insertNewPassword(hashedPassword, globalEmail)) {
            res.status(200).json({ success: true, route: '/signin' });
        } else {
            res.status(400).json({ success: true, error: 'Password not corrected!' });
        }

    } catch (error) {
        res.status(400).json({ success: false, error: '[ERROR] Sign up not successfull!' });
    }
};
