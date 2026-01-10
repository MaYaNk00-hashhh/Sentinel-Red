import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config({ path: '.env.local' });
dotenv.config();

// API Routes
import authRoutes from './routes/authRoutes';
import projectRoutes from './routes/projectRoutes';
import attackGraphRoutes from './routes/attackGraphRoutes';
import reportRoutes from './routes/reportRoutes';

const app = express();
const PORT = process.env.PORT || 3000;

console.log('Initializing Server...');

// Middleware
app.use(cors({
    origin: ['http://localhost:5173', 'http://localhost:5180', 'http://localhost:3000', 'http://localhost:4173'],
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

console.log('Registering Routes...');
app.use('/api/auth', authRoutes);
app.use('/api/projects', projectRoutes);
app.use('/api/attack-graph', attackGraphRoutes);
app.use('/api/reports', reportRoutes);
console.log('Routes Registered.');

// Debug middleware to log all hits
app.use((req, _res, next) => {
    console.log(`DEBUG: Incoming Request: ${req.method} ${req.originalUrl}`);
    next();
});

// Request logging middleware
app.use((req: Request, res: Response, next: NextFunction) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
    });
    next();
});

// Health check endpoint
app.get('/health', (_req: Request, res: Response) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// ... (skipping unchanged lines is implicit in replace_file_content logic if context is sufficient, but here I'll just target the error handler too)

// Global error handler
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    console.error(`[ERROR] ${new Date().toISOString()} - ${err.message}`);
    console.error(err.stack);

    res.status(500).json({
        error: true,
        message: process.env.NODE_ENV === 'development'
            ? err.message
            : 'Internal server error',
        timestamp: new Date().toISOString()
    });
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT received. Shutting down gracefully...');
    process.exit(0);
});

// Start server if run directly
const isStandalone = require.main === module || process.env.DEV_MODE === 'true';

if (isStandalone) {
    app.listen(PORT, () => {
        console.log(`
╔════════════════════════════════════════════════════════════╗
║                    Sentinel AI Backend                      ║
╠════════════════════════════════════════════════════════════╣
║  Server running on: http://localhost:${PORT}                   ║
║  Environment: ${(process.env.NODE_ENV || 'development').padEnd(42)}║
║  Started at: ${new Date().toISOString()}       ║
╚════════════════════════════════════════════════════════════╝
        `);
    });
}

export default app;
