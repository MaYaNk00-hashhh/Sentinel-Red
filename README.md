# Sentinel Red - AI-Powered Security Vulnerability Scanner

Sentinel Red is an autonomous security testing platform that uses AI to identify vulnerabilities in your applications. It provides attack graph visualization, detailed vulnerability reports, and actionable remediation recommendations.

## 🚀 Features

- **Automated Security Scanning**: Upload OpenAPI specs, source code, or target URLs for comprehensive security analysis
- **Attack Graph Visualization**: Interactive visualization of attack paths and vulnerability chains
- **AI-Powered Analysis**: Uses Google Gemini or AWS Bedrock for intelligent security recommendations
- **Real-time Scan Monitoring**: Watch scan progress with live logs
- **Detailed Reports**: Export comprehensive security reports with remediation guidance

## 📋 Prerequisites

- Node.js 18+ 
- npm or yarn
- Supabase account (for database)
- (Optional) Google Gemini API key or AWS Bedrock credentials for AI features

## 🛠️ Local Development Setup

### 1. Clone and Install Dependencies

```bash
# Navigate to the project directory
cd "H2S 2/H2S 2"

# Install frontend dependencies
npm install

# Install backend dependencies
cd backend
npm install
cd ..
```

### 2. Configure Environment Variables

#### Backend Configuration

Create a `.env.local` file in the `backend` directory:

```bash
# backend/.env.local

# Server Configuration
NODE_ENV=development
PORT=3000

# Database Configuration (Supabase)
# Get these from your Supabase project dashboard: https://app.supabase.com
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key-here

# Authentication
# Generate a secure random string (e.g., using: openssl rand -base64 32)
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production

# AI Service Configuration (Optional)
# Supports Google Gemini (starts with AIza) or AWS Bedrock (starts with ABSK)
LLM_API_KEY=
```

#### Frontend Configuration

Create a `.env.local` file in the root directory:

```bash
# .env.local

# API Configuration - points to local backend
VITE_API_BASE_URL=http://localhost:3000/api
```

### 3. Set Up Supabase Database

Create the following tables in your Supabase project:

```sql
-- Users table
CREATE TABLE users (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Projects table
CREATE TABLE projects (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    repo_url TEXT,
    openapi_spec TEXT,
    vulnerability_counts JSONB DEFAULT '{"critical": 0, "high": 0, "medium": 0, "low": 0}',
    last_scan_id UUID,
    last_scan_status VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Scans table
CREATE TABLE scans (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    status VARCHAR(50) DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    logs TEXT[] DEFAULT '{}',
    attack_graph JSONB,
    vulnerability_count INTEGER DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enable Row Level Security (optional but recommended)
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
```

### 4. Start Development Servers

```bash
# Option 1: Start both frontend and backend together
npm run full:dev

# Option 2: Start separately
# Terminal 1 - Backend
cd backend
npm run dev

# Terminal 2 - Frontend
npm run dev
```

The application will be available at:
- Frontend: http://localhost:5180
- Backend API: http://localhost:3000

## 🌐 Production Deployment (Vercel)

### 1. Prepare for Deployment

Ensure your `vercel.json` is configured correctly (already done):

```json
{
    "version": 2,
    "buildCommand": "npm run build",
    "outputDirectory": "dist",
    "installCommand": "npm install && cd backend && npm install",
    "framework": "vite",
    "functions": {
        "api/index.ts": {
            "runtime": "@vercel/node@3.0.0",
            "maxDuration": 30
        }
    },
    "rewrites": [
        {
            "source": "/api/:path*",
            "destination": "/api"
        },
        {
            "source": "/((?!api).*)",
            "destination": "/index.html"
        }
    ]
}
```

### 2. Deploy to Vercel

```bash
# Install Vercel CLI if not already installed
npm install -g vercel

# Login to Vercel
vercel login

# Deploy
vercel
```

### 3. Configure Environment Variables in Vercel

Go to your Vercel project settings and add the following environment variables:

| Variable | Value | Description |
|----------|-------|-------------|
| `NODE_ENV` | `production` | Environment mode |
| `SUPABASE_URL` | `https://your-project.supabase.co` | Your Supabase URL |
| `SUPABASE_SERVICE_ROLE_KEY` | `your-key` | Supabase service role key |
| `JWT_SECRET` | `your-secret` | JWT signing secret |
| `LLM_API_KEY` | `your-api-key` | (Optional) AI service API key |
| `VITE_API_BASE_URL` | `/api` | API base URL for frontend |

### 4. Redeploy

After setting environment variables, trigger a new deployment:

```bash
vercel --prod
```

## 📁 Project Structure

```
H2S 2/H2S 2/
├── api/                    # Vercel serverless function entry point
│   └── index.ts
├── backend/                # Express.js backend
│   ├── src/
│   │   ├── controllers/    # Route handlers
│   │   ├── db/             # Database configuration
│   │   ├── routes/         # API routes
│   │   ├── services/       # Business logic
│   │   ├── utils/          # Utility functions
│   │   └── server.ts       # Express app entry
│   └── package.json
├── src/                    # React frontend
│   ├── components/         # Reusable UI components
│   ├── hooks/              # Custom React hooks
│   ├── lib/                # Utilities and API client
│   ├── pages/              # Page components
│   ├── services/           # API service functions
│   ├── stores/             # Zustand state stores
│   ├── types/              # TypeScript type definitions
│   └── App.tsx             # Main app component
├── .env.local              # Frontend environment variables
├── package.json            # Frontend dependencies
├── vercel.json             # Vercel deployment config
└── vite.config.ts          # Vite configuration
```

## 🔧 API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `GET /api/auth/me` - Get current user

### Projects
- `GET /api/projects` - List all projects
- `GET /api/projects/:id` - Get project details
- `POST /api/projects` - Create new project
- `DELETE /api/projects/:id` - Delete project
- `GET /api/projects/:id/endpoints` - Get project endpoints
- `GET /api/projects/:id/history` - Get scan history

### Scans
- `POST /api/projects/:id/scan` - Start new scan
- `GET /api/projects/scan/:scanId` - Get scan status
- `GET /api/projects/scan/:scanId/logs` - Get scan logs

### Attack Graph
- `GET /api/attack-graph/:scanId` - Get attack graph
- `GET /api/attack-graph/node/:nodeId` - Get node details
- `PUT /api/attack-graph/:scanId` - Update attack graph
- `POST /api/attack-graph/:scanId/analyze` - Analyze graph

## 🐛 Troubleshooting

### Common Issues

1. **CORS Errors**
   - Ensure the backend CORS configuration includes your frontend URL
   - Check that `credentials: true` is set in both frontend and backend

2. **Database Connection Errors**
   - Verify your Supabase URL and service role key are correct
   - Check that the required tables exist in your database

3. **Authentication Issues**
   - Ensure JWT_SECRET is set and consistent
   - Check that tokens are being stored in localStorage

4. **Build Errors on Vercel**
   - Ensure all dependencies are listed in package.json
   - Check that TypeScript types are correctly installed

### Debug Mode

Enable debug logging by setting:
```bash
NODE_ENV=development
```

## 📝 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📧 Support

For issues and feature requests, please open a GitHub issue.
