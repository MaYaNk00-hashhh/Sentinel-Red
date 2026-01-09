import { Router } from 'express';
import { login, register, getCurrentUser } from '../controllers/authController';

const router = Router();

router.post('/login', login);
router.post('/register', register);
router.get('/me', getCurrentUser);

export default router;
