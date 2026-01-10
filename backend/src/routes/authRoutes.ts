import { Router } from 'express';
import { login, register, getCurrentUser, refreshToken, logout } from '../controllers/authController';

const router = Router();

router.post('/login', login);
router.post('/register', register);
router.post('/refresh', refreshToken);
router.post('/logout', logout);
router.get('/me', getCurrentUser);

export default router;
