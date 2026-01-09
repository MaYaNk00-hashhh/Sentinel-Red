import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { supabase } from '../db/supabase';

const JWT_SECRET = process.env.JWT_SECRET || 'secret-key-hackathon';

export const register = async (req: Request, res: Response) => {
    const { name, email, password } = req.body;

    // Check if user exists
    const { data: existingUser } = await supabase
        .from('users')
        .select('id')
        .eq('email', email)
        .single();

    if (existingUser) {
        return res.status(400).json({ message: 'User already exists' });
    }

    const { data: newUser, error } = await supabase
        .from('users')
        .insert([{
            name,
            email,
            password, // Note: In production, hash this with bcrypt!
            role: 'user',
            created_at: new Date().toISOString()
        }])
        .select()
        .single();

    if (error) return res.status(500).json({ error: error.message });

    const token = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '1h' });

    res.status(201).json({
        user: { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role },
        token,
        refresh_token: uuidv4()
    });
};

export const login = async (req: Request, res: Response) => {
    const { email, password } = req.body;

    const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('email', email)
        .eq('password', password) // Validating against stored plaintext/hash
        .single();

    if (error || !user) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

    res.json({
        user: { id: user.id, name: user.name, email: user.email, role: user.role },
        token,
        refresh_token: uuidv4()
    });
};

export const getCurrentUser = async (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: 'No token' });

    const token = authHeader.split(' ')[1];

    try {
        const decoded: any = jwt.verify(token, JWT_SECRET);

        const { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('id', decoded.id)
            .single();

        if (!user) return res.status(404).json({ message: 'User not found' });

        res.json(user);
    } catch (e) {
        return res.status(401).json({ message: 'Invalid token' });
    }
};
