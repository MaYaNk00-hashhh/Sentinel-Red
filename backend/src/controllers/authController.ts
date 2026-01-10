import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { supabase } from '../db/supabase';

const JWT_SECRET = process.env.JWT_SECRET || 'secret-key-hackathon';
const ACCESS_TOKEN_EXPIRY = '1h';

// In-memory store for refresh tokens (in production, use Redis or database)
const refreshTokenStore: Map<string, { userId: string; email: string }> = new Map();

export const register = async (req: Request, res: Response) => {
    try {
        const { name, email, password } = req.body;

        // Validate input
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'Name, email, and password are required' });
        }

        if (password.length < 8) {
            return res.status(400).json({ message: 'Password must be at least 8 characters' });
        }

        // Check if user exists
        const { data: existingUser } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .single();

        if (existingUser) {
            return res.status(400).json({ message: 'User already exists with this email' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        const { data: newUser, error } = await supabase
            .from('users')
            .insert([{
                name,
                email,
                password: hashedPassword,
                role: 'user',
                created_at: new Date().toISOString()
            }])
            .select()
            .single();

        if (error) {
            console.error('Registration error:', error);
            return res.status(500).json({ message: 'Failed to create user', error: error.message });
        }

        const token = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
        const refreshToken = uuidv4();

        // Store refresh token
        refreshTokenStore.set(refreshToken, { userId: newUser.id, email: newUser.email });

        res.status(201).json({
            user: { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role, created_at: newUser.created_at },
            token,
            access_token: token,
            refresh_token: refreshToken
        });
    } catch (error: any) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Internal server error', error: error.message });
    }
};

export const login = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        // Get user by email
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Check password - support both hashed and plain text for backward compatibility
        let passwordValid = false;

        // Try bcrypt comparison first
        try {
            passwordValid = await bcrypt.compare(password, user.password);
        } catch {
            // If bcrypt fails, try plain text comparison (legacy)
            passwordValid = user.password === password;
        }

        if (!passwordValid) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
        const refreshToken = uuidv4();

        // Store refresh token
        refreshTokenStore.set(refreshToken, { userId: user.id, email: user.email });

        res.json({
            user: { id: user.id, name: user.name, email: user.email, role: user.role, created_at: user.created_at },
            token,
            access_token: token,
            refresh_token: refreshToken
        });
    } catch (error: any) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error', error: error.message });
    }
};

export const refreshToken = async (req: Request, res: Response) => {
    try {
        const { refresh_token } = req.body;

        if (!refresh_token) {
            return res.status(400).json({ message: 'Refresh token is required' });
        }

        // Validate refresh token
        const tokenData = refreshTokenStore.get(refresh_token);

        if (!tokenData) {
            return res.status(401).json({ message: 'Invalid refresh token' });
        }

        // Generate new access token
        const newAccessToken = jwt.sign(
            { id: tokenData.userId, email: tokenData.email },
            JWT_SECRET,
            { expiresIn: ACCESS_TOKEN_EXPIRY }
        );

        // Generate new refresh token and invalidate old one
        const newRefreshToken = uuidv4();
        refreshTokenStore.delete(refresh_token);
        refreshTokenStore.set(newRefreshToken, tokenData);

        res.json({
            access_token: newAccessToken,
            token: newAccessToken,
            refresh_token: newRefreshToken
        });
    } catch (error: any) {
        console.error('Token refresh error:', error);
        res.status(500).json({ message: 'Internal server error', error: error.message });
    }
};

export const getCurrentUser = async (req: Request, res: Response) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ message: 'No authorization token provided' });
        }

        const token = authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ message: 'Invalid authorization header format' });
        }

        const decoded: any = jwt.verify(token, JWT_SECRET);

        const { data: user, error } = await supabase
            .from('users')
            .select('id, name, email, role, created_at')
            .eq('id', decoded.id)
            .single();

        if (error || !user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json(user);
    } catch (e: any) {
        if (e.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expired' });
        }
        if (e.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Invalid token' });
        }
        console.error('Get current user error:', e);
        return res.status(401).json({ message: 'Authentication failed' });
    }
};

export const logout = async (req: Request, res: Response) => {
    try {
        const { refresh_token } = req.body;

        if (refresh_token) {
            refreshTokenStore.delete(refresh_token);
        }

        res.json({ message: 'Logged out successfully' });
    } catch (error: any) {
        console.error('Logout error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};
