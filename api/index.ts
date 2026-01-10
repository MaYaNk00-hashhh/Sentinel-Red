import type { IncomingMessage, ServerResponse } from 'http';
import app from '../backend/src/server';

// Export the Express app as a Vercel serverless function
// Using native Node.js types for compatibility
export default function handler(req: IncomingMessage, res: ServerResponse) {
    // Handle the request with Express
    return app(req as any, res as any);
}
