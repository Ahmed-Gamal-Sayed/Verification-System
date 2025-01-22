import express from 'express';
import { signin, signup, changePassword, checkEmail, verifyEmail } from '../controllers/auth.controller.js';



const router = express.Router();

router.post('/signin', signin);
router.post('/signup', signup);
router.post('/verify-email', verifyEmail);
router.post('/check-email', checkEmail);
router.post('/change-password', changePassword);

export default router;
