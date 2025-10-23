# CampusAuth

> **Simple, Secure, Scalable Authentication for Modern JavaScript Apps**

CampusAuth helps you integrate authentication into your **Node.js**, **Express**, and **Next.js** applications effortlessly.  
It supports **JWT**, **Role-based Access Control (RBAC)**, and **OAuth providers** (Google, GitHub).

---

## Features

- **Plug-and-play Authentication** — Works out of the box with Express and Next.js  
- **JWT + Refresh Tokens** — Secure token-based sessions  
- **Role-based Access Control (RBAC)** — Define roles and protect routes easily  
- **OAuth Integration** — Google, GitHub (more coming soon)  
- **MongoDB Ready** — Built-in support for MongoDB user persistence  
- **Next.js App Router** — Protect API routes & pages seamlessly  
- **TypeScript Support** — Fully typed for reliability and autocompletion  

---

## Installation

```bash
npm install campusauth
```

or

```bash
yarn add campusauth
```

---

## Setup Options

Choose your preferred setup:

1. **[MERN Stack Backend](#mern-stack-backend-setup)** - Separate Express.js backend + React/Next.js frontend
2. **[Full-Stack Next.js with App Router](#full-stack-nextjs-with-app-router)** - All-in-one Next.js application

---

## MERN Stack Backend Setup

### Backend Project Structure

```
backend/
├── src/
│   ├── controllers/
│   │   ├── authController.js
│   │   └── userController.js
│   ├── middleware/
│   │   ├── auth.js
│   │   └── cors.js
│   ├── routes/
│   │   ├── auth.js
│   │   └── users.js
│   ├── config/
│   │   └── database.js
│   ├── models/
│   │   └── User.js (optional, using CampusAuth User model)
│   └── app.js
├── .env
├── server.js
└── package.json
```

### Step 1: Backend Environment Setup

Create `.env` in backend directory:

```bash
# MongoDB Configuration
MONGO_URI=mongodb://localhost:27017/campusauth
# For MongoDB Atlas: mongodb+srv://username:password@cluster.mongodb.net/dbname

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-min-32-characters
JWT_REFRESH_SECRET=your-refresh-secret-key-min-32-characters
JWT_EXPIRES_IN=1h
JWT_REFRESH_EXPIRES_IN=7d

# Google OAuth (Optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_CALLBACK_URL=http://localhost:5000/api/auth/oauth/google/callback

# GitHub OAuth (Optional)
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_CALLBACK_URL=http://localhost:5000/api/auth/oauth/github/callback

# Server Configuration
PORT=5000
NODE_ENV=development
FRONTEND_URL=http://localhost:3000

# CORS
CORS_ORIGIN=http://localhost:3000
```

### Step 2: Backend Dependencies

```bash
npm install campusauth express mongoose cors helmet dotenv
npm install -D nodemon @types/node
```

### Step 3: Express Server Setup

Create `server.js`:

```javascript
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const dotenv = require('dotenv');
const {
  connectDB,
  setupOAuth,
  authRoutes,
  oauthRoutes,
  errorHandler,
  config,
} = require('campusauth');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Initialize database and start server
async function startServer() {
  try {
    // Connect to MongoDB
    await connectDB(process.env.MONGO_URI);

    // Configure CampusAuth
    config.set({
      jwtSecret: process.env.JWT_SECRET,
      jwtRefreshSecret: process.env.JWT_REFRESH_SECRET,
      jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1h',
      jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    });

    // Setup OAuth providers
    setupOAuth();

    // Security middleware
    app.use(helmet());
    app.use(cors({
      origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
      credentials: true,
    }));

    // Body parsing middleware
    app.use(express.json({ limit: '10mb' }));
    app.use(express.urlencoded({ extended: true }));

    // Health check
    app.get('/api/health', (req, res) => {
      res.json({ 
        status: 'OK', 
        message: 'CampusAuth Backend is running',
        timestamp: new Date().toISOString() 
      });
    });

    // Authentication routes
    app.use('/api/auth', authRoutes);
    app.use('/api/auth/oauth', oauthRoutes);

    // Protected routes example
    app.use('/api/users', require('./src/routes/users'));

    // Error handling middleware (must be last)
    app.use(errorHandler);

    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
      console.log(`📚 API Documentation: http://localhost:${PORT}/api/health`);
    });

  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

startServer();
```

### Step 4: Protected Routes Example

Create `src/routes/users.js`:

```javascript
const express = require('express');
const { protect, requireAdmin, User, ResponseUtil } = require('campusauth');

const router = express.Router();

// Get current user profile
router.get('/profile', protect(), async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password -refreshToken');
    ResponseUtil.success(res, user, 'User profile retrieved');
  } catch (error) {
    ResponseUtil.serverError(res, 'Failed to get user profile');
  }
});

// Update user profile
router.put('/profile', protect(), async (req, res) => {
  try {
    const { name } = req.body;
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { name },
      { new: true }
    ).select('-password -refreshToken');
    
    ResponseUtil.success(res, user, 'Profile updated successfully');
  } catch (error) {
    ResponseUtil.serverError(res, 'Failed to update profile');
  }
});

// Admin: Get all users
router.get('/all', protect(), requireAdmin(), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const users = await User.find()
      .select('-password -refreshToken')
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });

    const total = await User.countDocuments();

    ResponseUtil.success(res, {
      users,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    }, 'Users retrieved successfully');
  } catch (error) {
    ResponseUtil.serverError(res, 'Failed to get users');
  }
});

// Admin: Update user role
router.put('/:userId/role', protect(), requireAdmin(), async (req, res) => {
  try {
    const { role } = req.body;
    const { userId } = req.params;

    if (!['user', 'admin', 'moderator'].includes(role)) {
      return ResponseUtil.error(res, 'Invalid role', 400);
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { role },
      { new: true }
    ).select('-password -refreshToken');

    if (!user) {
      return ResponseUtil.notFound(res, 'User not found');
    }

    ResponseUtil.success(res, user, 'User role updated successfully');
  } catch (error) {
    ResponseUtil.serverError(res, 'Failed to update user role');
  }
});

module.exports = router;
```

### Step 5: Frontend Integration (React/Next.js)

Create a React context for auth in your frontend:

```typescript
// frontend/src/contexts/AuthContext.tsx
import React, { createContext, useContext, useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000/api';

interface User {
  _id: string;
  name: string;
  email: string;
  role: string;
  provider: string;
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<{ success: boolean; error?: string }>;
  register: (name: string, email: string, password: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => Promise<void>;
  token: string | null;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: React.ReactNode;
}

export const AuthProvider = ({ children }: AuthProviderProps) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [token, setToken] = useState<string | null>(null);
  const router = useRouter();

  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    try {
      const response = await fetch('/api/auth/me', {
        credentials: 'include',
      });

      if (response.ok) {
        const data = await response.json();
        if (data.success) {
          setUser(data.data);
        }
      }
    } catch (error) {
      console.error('Auth check failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const login = async (email: string, password: string) => {
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (data.success) {
        setUser(data.data.user);
        return { success: true };
      } else {
        return { success: false, error: data.error };
      }
    } catch (error) {
      console.error('Login failed:', error);
      return { success: false, error: 'Network error occurred' };
    }
  };

  const register = async (name: string, email: string, password: string) => {
    try {
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ name, email, password }),
      });

      const data = await response.json();

      if (data.success) {
        setUser(data.data.user);
        return { success: true };
      } else {
        return { success: false, error: data.error };
      }
    } catch (error) {
      console.error('Registration failed:', error);
      return { success: false, error: 'Network error occurred' };
    }
  };

  const logout = async () => {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include',
      });
    } catch (error) {
      console.error('Logout failed:', error);
    } finally {
      setUser(null);
      router.push('/login');
    }
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, token }}>
      {children}
    </AuthContext.Provider>
  );
};
```

---

## Full-Stack Next.js with App Router

### Project Structure

```
my-nextjs-app/
├── app/
│   ├── (auth)/
│   │   ├── login/
│   │   │   └── page.tsx
│   │   └── register/
│   │       └── page.tsx
│   ├── dashboard/
│   │   ├── page.tsx
│   │   └── layout.tsx
│   ├── admin/
│   │   ├── users/
│   │   │   └── page.tsx
│   │   └── layout.tsx
│   ├── api/
│   │   └── auth/
│   │       ├── [...slug]/
│   │       │   └── route.ts
│   │       └── oauth/
│   │           ├── google/
│   │           │   └── callback/
│   │           │       └── route.ts
│   │           └── github/
│   │               └── callback/
│   │                   └── route.ts
│   ├── globals.css
│   ├── layout.tsx
│   └── page.tsx
├── components/
│   ├── auth/
│   │   ├── LoginForm.tsx
│   │   ├── RegisterForm.tsx
│   │   └── AuthProvider.tsx
│   ├── ui/
│   │   ├── Button.tsx
│   │   └── Input.tsx
│   └── layout/
│       ├── Navbar.tsx
│       └── ProtectedRoute.tsx
├── lib/
│   ├── auth.ts
│   ├── db.ts
│   └── utils.ts
├── hooks/
│   └── useAuth.ts
├── middleware.ts
├── .env.local
└── package.json
```

### Step 1: Environment Configuration

Create `.env.local`:

```bash
# MongoDB Configuration
MONGO_URI=mongodb://localhost:27017/campusauth
# For MongoDB Atlas: mongodb+srv://username:password@cluster.mongodb.net/dbname

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-min-32-characters
JWT_REFRESH_SECRET=your-refresh-secret-key-min-32-characters
JWT_EXPIRES_IN=1h
JWT_REFRESH_EXPIRES_IN=7d

# Google OAuth (Optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_CALLBACK_URL=http://localhost:3000/api/auth/oauth/google/callback

# GitHub OAuth (Optional)
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_CALLBACK_URL=http://localhost:3000/api/auth/oauth/github/callback

# Next.js Configuration
NEXTAUTH_URL=http://localhost:3000
NEXTAUTH_SECRET=your-nextauth-secret-key

# Server Configuration
NODE_ENV=development
```

### Step 2: Dependencies Installation

```bash
npm install campusauth mongoose jose
npm install -D typescript @types/node @types/react tailwindcss
```

### Step 3: Database and Auth Configuration

Create `lib/db.ts`:

```typescript
// lib/db.ts
import { connectDB } from 'campusauth';

let isConnected = false;

export async function dbConnect() {
  if (isConnected) return;

  try {
    await connectDB(process.env.MONGO_URI!);
    isConnected = true;
    console.log('✅ Database connected successfully');
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    throw error;
  }
}
```

Create `lib/auth.ts`:

```typescript
// lib/auth.ts
import { config, setupOAuth } from 'campusauth';

// Configure CampusAuth
config.set({
  jwtSecret: process.env.JWT_SECRET!,
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET!,
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1h',
  jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
});

// Setup OAuth (server-side only)
if (typeof window === 'undefined') {
  setupOAuth();
}

export { config };
```

### Step 4: API Routes with App Router

Create `app/api/auth/[...slug]/route.ts`:

```typescript
// app/api/auth/[...slug]/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { 
  User, 
  hashPassword, 
  verifyPassword, 
  generateTokenPair, 
  verifyRefreshToken,
  verifyToken,
  ValidationUtil,
  ResponseUtil,
  logger 
} from 'campusauth';
import { dbConnect } from '../../../../lib/db';
import '../../../../lib/auth';

// Ensure database connection
dbConnect();

export async function POST(
  request: NextRequest,
  { params }: { params: { slug: string[] } }
) {
  const path = params.slug.join('/');
  
  try {
    switch (path) {
      case 'register':
        return handleRegister(request);
      case 'login':
        return handleLogin(request);
      case 'refresh':
        return handleRefresh(request);
      case 'logout':
        return handleLogout(request);
      default:
        return NextResponse.json({ error: 'Endpoint not found' }, { status: 404 });
    }
  } catch (error: any) {
    logger.error('API Error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

export async function GET(
  request: NextRequest,
  { params }: { params: { slug: string[] } }
) {
  const path = params.slug.join('/');
  
  try {
    switch (path) {
      case 'me':
        return handleGetMe(request);
      default:
        return NextResponse.json({ error: 'Endpoint not found' }, { status: 404 });
    }
  } catch (error: any) {
    logger.error('API Error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

async function handleRegister(request: NextRequest) {
  const body = await request.json();
  const { name, email, password } = body;

  // Validate required fields
  const validation = ValidationUtil.validateRequiredFields(body, ['name', 'email', 'password']);
  if (!validation.valid) {
    return NextResponse.json({
      success: false,
      error: `Missing fields: ${validation.missing?.join(', ')}`
    }, { status: 400 });
  }

  // Validate email
  if (!ValidationUtil.isEmail(email)) {
    return NextResponse.json({
      success: false,
      error: 'Invalid email format'
    }, { status: 400 });
  }

  // Validate password strength
  const passwordValidation = ValidationUtil.isStrongPassword(password);
  if (!passwordValidation.valid) {
    return NextResponse.json({
      success: false,
      error: passwordValidation.message
    }, { status: 400 });
  }

  // Check if user exists
  const existing = await User.findOne({ email: email.toLowerCase() });
  if (existing) {
    return NextResponse.json({
      success: false,
      error: 'User already exists'
    }, { status: 409 });
  }

  // Create user
  const hashedPassword = await hashPassword(password);
  const user = await User.create({
    name: ValidationUtil.sanitizeInput(name),
    email: email.toLowerCase(),
    password: hashedPassword,
    provider: 'local',
  });

  // Generate tokens
  const tokens = generateTokenPair({ id: user._id!.toString(), email: user.email });

  // Save refresh token
  user.refreshToken = tokens.refreshToken;
  await user.save();

  // Set HTTP-only cookies
  const response = NextResponse.json({
    success: true,
    message: 'Registration successful',
    data: {
      user: user.toJSON(),
      ...tokens,
    }
  }, { status: 201 });

  response.cookies.set('accessToken', tokens.accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 3600, // 1 hour
  });

  response.cookies.set('refreshToken', tokens.refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 604800, // 7 days
  });

  return response;
}

async function handleLogin(request: NextRequest) {
  const body = await request.json();
  const { email, password } = body;

  // Validate required fields
  const validation = ValidationUtil.validateRequiredFields(body, ['email', 'password']);
  if (!validation.valid) {
    return NextResponse.json({
      success: false,
      error: `Missing fields: ${validation.missing?.join(', ')}`
    }, { status: 400 });
  }

  // Find user
  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user || !user.password) {
    return NextResponse.json({
      success: false,
      error: 'Invalid credentials'
    }, { status: 401 });
  }

  // Verify password
  const isValid = await verifyPassword(password, user.password);
  if (!isValid) {
    return NextResponse.json({
      success: false,
      error: 'Invalid credentials'
    }, { status: 401 });
  }

  // Generate tokens
  const tokens = generateTokenPair({ 
    id: user._id!.toString(), 
    email: user.email, 
    role: user.role 
  });

  // Save refresh token
  user.refreshToken = tokens.refreshToken;
  await user.save();

  // Set HTTP-only cookies
  const response = NextResponse.json({
    success: true,
    message: 'Login successful',
    data: {
      user: user.toJSON(),
      ...tokens,
    }
  });

  response.cookies.set('accessToken', tokens.accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 3600,
  });

  response.cookies.set('refreshToken', tokens.refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 604800,
  });

  return response;
}

async function handleRefresh(request: NextRequest) {
  const refreshToken = request.cookies.get('refreshToken')?.value;

  if (!refreshToken) {
    return NextResponse.json({
      success: false,
      error: 'Refresh token required'
    }, { status: 400 });
  }

  try {
    // Verify refresh token
    const decoded = verifyRefreshToken(refreshToken);

    // Find user and verify refresh token matches
    const user = await User.findById(decoded.id);
    if (!user || user.refreshToken !== refreshToken) {
      return NextResponse.json({
        success: false,
        error: 'Invalid refresh token'
      }, { status: 401 });
    }

    // Generate new tokens
    const tokens = generateTokenPair({ 
      id: user._id!.toString(), 
      email: user.email, 
      role: user.role 
    });

    // Update refresh token
    user.refreshToken = tokens.refreshToken;
    await user.save();

    const response = NextResponse.json({
      success: true,
      message: 'Token refreshed',
      data: tokens
    });

    // Update cookies
    response.cookies.set('accessToken', tokens.accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600,
    });

    response.cookies.set('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 604800,
    });

    return response;
  } catch (error) {
    return NextResponse.json({
      success: false,
      error: 'Invalid refresh token'
    }, { status: 401 });
  }
}

async function handleLogout(request: NextRequest) {
  const token = request.cookies.get('accessToken')?.value;

  if (token) {
    try {
      const decoded = verifyToken(token);
      const user = await User.findById(decoded.id);
      if (user) {
        user.refreshToken = undefined;
        await user.save();
      }
    } catch (error) {
      // Token might be expired, continue with logout
    }
  }

  const response = NextResponse.json({
    success: true,
    message: 'Logged out successfully',
    data: null
  });

  // Clear cookies
  response.cookies.delete('accessToken');
  response.cookies.delete('refreshToken');

  return response;
}

async function handleGetMe(request: NextRequest) {
  const token = request.cookies.get('accessToken')?.value;

  if (!token) {
    return NextResponse.json({
      success: false,
      error: 'No token provided'
    }, { status: 401 });
  }

  try {
    const decoded = verifyToken(token);
    const user = await User.findById(decoded.id).select('-password -refreshToken');

    if (!user) {
      return NextResponse.json({
        success: false,
        error: 'User not found'
      }, { status: 401 });
    }

    return NextResponse.json({
      success: true,
      message: 'User retrieved',
      data: user.toJSON()
    });
  } catch (error: any) {
    if (error.name === 'TokenExpiredError') {
      return NextResponse.json({
        success: false,
        error: 'Token expired'
      }, { status: 401 });
    }

    return NextResponse.json({
      success: false,
      error: 'Invalid token'
    }, { status: 401 });
  }
}
```

### Step 5: OAuth Callback Routes

Create `app/api/auth/oauth/google/callback/route.ts`:

```typescript
// app/api/auth/oauth/google/callback/route.ts
import { NextRequest, NextResponse } from 'next/server';
import passport from 'passport';
import { generateTokenPair, User } from 'campusauth';
import { dbConnect } from '../../../../../../lib/db';
import '../../../../../../lib/auth';

export async function GET(request: NextRequest) {
  await dbConnect();

  return new Promise((resolve) => {
    passport.authenticate('google', { session: false }, async (err: any, user: any) => {
      if (err || !user) {
        const response = NextResponse.redirect(new URL('/login?error=oauth_failed', request.url));
        resolve(response);
        return;
      }

      try {
        const tokens = generateTokenPair({
          id: user._id.toString(),
          email: user.email,
          role: user.role,
        });

        // Save refresh token
        await User.findByIdAndUpdate(user._id, { refreshToken: tokens.refreshToken });

        const response = NextResponse.redirect(new URL('/dashboard', request.url));

        // Set HTTP-only cookies
        response.cookies.set('accessToken', tokens.accessToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 3600,
        });

        response.cookies.set('refreshToken', tokens.refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 604800,
        });

        resolve(response);
      } catch (error) {
        const response = NextResponse.redirect(new URL('/login?error=token_failed', request.url));
        resolve(response);
      }
    })(request);
  });
}
```

### Step 6: Middleware for App Router

Create `middleware.ts`:

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { jwtVerify } from 'jose';

const protectedPaths = ['/dashboard', '/profile', '/admin'];
const publicPaths = ['/login', '/register', '/', '/about'];
const adminPaths = ['/admin'];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Check if path is public
  if (publicPaths.some(path => pathname.startsWith(path))) {
    return NextResponse.next();
  }

  // Check if path is protected
  const isProtected = protectedPaths.some(path => pathname.startsWith(path));

  if (isProtected) {
    const token = request.cookies.get('accessToken')?.value;

    if (!token) {
      return NextResponse.redirect(new URL('/login', request.url));
    }

    try {
      // Verify JWT token
      const secret = new TextEncoder().encode(process.env.JWT_SECRET);
      const { payload } = await jwtVerify(token, secret);

      // Check admin access
      if (adminPaths.some(path => pathname.startsWith(path))) {
        if (payload.role !== 'admin') {
          return NextResponse.redirect(new URL('/dashboard?error=access_denied', request.url));
        }
      }

      return NextResponse.next();
    } catch (error) {
      // Token expired or invalid, try to refresh
      const refreshToken = request.cookies.get('refreshToken')?.value;
      
      if (refreshToken) {
        try {
          // Attempt to refresh token
          const response = await fetch(new URL('/api/auth/refresh', request.url), {
            method: 'POST',
            headers: {
              'Cookie': `refreshToken=${refreshToken}`,
            },
          });

          if (response.ok) {
            // Token refreshed successfully, continue
            return NextResponse.next();
          }
        } catch (refreshError) {
          // Refresh failed, redirect to login
        }
      }

      return NextResponse.redirect(new URL('/login?error=session_expired', request.url));
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};
```

### Step 7: Auth Hook for App Router

Create `hooks/useAuth.ts`:

```typescript
// hooks/useAuth.ts
'use client';

import { useState, useEffect, createContext, useContext, ReactNode } from 'react';
import { useRouter } from 'next/navigation';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000/api';

interface User {
  _id: string;
  name: string;
  email: string;
  role: string;
  provider: string;
  createdAt: string;
  updatedAt: string;
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<{ success: boolean; error?: string }>;
  register: (name: string, email: string, password: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => Promise<void>;
  refreshToken: () => Promise<boolean>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider = ({ children }: AuthProviderProps) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    try {
      const response = await fetch('/api/auth/me', {
        credentials: 'include',
      });

      if (response.ok) {
        const data = await response.json();
        if (data.success) {
          setUser(data.data);
        }
      }
    } catch (error) {
      console.error('Auth check failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const login = async (email: string, password: string) => {
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (data.success) {
        setUser(data.data.user);
        return { success: true };
      } else {
        return { success: false, error: data.error };
      }
    } catch (error) {
      console.error('Login failed:', error);
      return { success: false, error: 'Network error occurred' };
    }
  };

  const register = async (name: string, email: string, password: string) => {
    try {
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ name, email, password }),
      });

      const data = await response.json();

      if (data.success) {
        setUser(data.data.user);
        return { success: true };
      } else {
        return { success: false, error: data.error };
      }
    } catch (error) {
      console.error('Registration failed:', error);
      return { success: false, error: 'Network error occurred' };
    }
  };

  const logout = async () => {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include',
      });
    } catch (error) {
      console.error('Logout failed:', error);
    } finally {
      setUser(null);
      router.push('/login');
    }
  };

  const refreshToken = async (): Promise<boolean> => {
    try {
      const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        credentials: 'include',
      });

      if (response.ok) {
        await checkAuth(); // Refresh user data
        return true;
      }
      return false;
    } catch (error) {
      console.error('Token refresh failed:', error);
      return false;
    }
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, refreshToken }}>
      {children}
    </AuthContext.Provider>
  );
};
```

### Step 8: App Router Layout and Pages

Create `app/layout.tsx`:

```typescript
// app/layout.tsx
import { Inter } from 'next/font/google';
import { AuthProvider } from '../hooks/useAuth';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export const metadata = {
  title: 'CampusAuth App',
  description: 'Secure authentication with CampusAuth',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
```

Create `app/(auth)/login/page.tsx`:

```typescript
// app/(auth)/login/page.tsx
'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '../../../hooks/useAuth';
import Link from 'next/link';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { login } = useAuth();
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    const result = await login(email, password);

    if (result.success) {
      router.push('/dashboard');
    } else {
      setError(result.error || 'Login failed');
    }

    setLoading(false);
  };

  const handleOAuthLogin = (provider: string) => {
    window.location.href = `/api/auth/oauth/${provider}`;
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Sign in to your account
          </h2>
        </div>
        
        {error && (
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
            {error}
          </div>
        )}

        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div className="rounded-md shadow-sm -space-y-px">
            <div>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-t-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                placeholder="Email address"
              />
            </div>
            <div>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-b-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                placeholder="Password"
              />
            </div>
          </div>

          <div>
            <button
              type="submit"
              disabled={loading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
            >
              {loading ? 'Signing in...' : 'Sign in'}
            </button>
          </div>

          <div className="mt-6">
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-300" />
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-gray-50 text-gray-500">Or continue with</span>
              </div>
            </div>

            <div className="mt-6 grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => handleOAuthLogin('google')}
                className="w-full inline-flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-500 hover:bg-gray-50"
              >
                Google
              </button>
              <button
                type="button"
                onClick={() => handleOAuthLogin('github')}
                className="w-full inline-flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-500 hover:bg-gray-50"
              >
                GitHub
              </button>
            </div>
          </div>

          <div className="text-center">
            <Link href="/register" className="text-indigo-600 hover:text-indigo-500">
              Don't have an account? Sign up
            </Link>
          </div>
        </form>
      </div>
    </div>
  );
}
```

Create `app/dashboard/page.tsx`:

```typescript
// app/dashboard/page.tsx
'use client';

import { useAuth } from '../../hooks/useAuth';
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';

export default function DashboardPage() {
  const { user, loading, logout } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user) {
      router.push('/login');
    }
  }, [user, loading, router]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-indigo-500"></div>
      </div>
    );
  }

  if (!user) {
    return null;
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <h1 className="text-xl font-semibold text-gray-900">Dashboard</h1>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-gray-700">Welcome, {user.name}</span>
              <button
                onClick={logout}
                className="bg-red-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <h2 className="text-lg font-medium text-gray-900 mb-4">User Information</h2>
              <dl className="grid grid-cols-1 gap-x-4 gap-y-6 sm:grid-cols-2">
                <div>
                  <dt className="text-sm font-medium text-gray-500">Name</dt>
                  <dd className="mt-1 text-sm text-gray-900">{user.name}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Email</dt>
                  <dd className="mt-1 text-sm text-gray-900">{user.email}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Role</dt>
                  <dd className="mt-1 text-sm text-gray-900 capitalize">{user.role}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Provider</dt>
                  <dd className="mt-1 text-sm text-gray-900 capitalize">{user.provider}</dd>
                </div>
              </dl>
              
              {user.role === 'admin' && (
                <div className="mt-6">
                  <button
                    onClick={() => router.push('/admin/users')}
                    className="bg-indigo-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  >
                    Admin Panel
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
```

---

## API Endpoints Reference

### Authentication Routes

#### Register User
```http
POST /auth/register
Content-Type: application/json

{
  "name": "Deepak Kumar",
  "email": "deepak@example.com",
  "password": "SecurePass123"
}
```

**Response (201):**
```json
{
  "success": true,
  "message": "Registration successful",
  "data": {
    "user": {
      "_id": "507f1f77bcf86cd799439011",
      "name": "Deepak Kumar",
      "email": "deepak@example.com",
      "role": "user",
      "provider": "local",
      "createdAt": "2024-01-15T10:30:00.000Z"
    },
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

#### Login User
```http
POST /auth/login
Content-Type: application/json

{
  "email": "deepak@example.com",
  "password": "SecurePass123"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": { /* user object */ },
    "accessToken": "eyJhbGc...",
    "refreshToken": "eyJhbGc..."
  }
}
```

#### Refresh Token
```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Token refreshed",
  "data": {
    "accessToken": "eyJhbGc...",
    "refreshToken": "eyJhbGc..."
  }
}
```

#### Get Current User
```http
GET /auth/me
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200):**
```json
{
  "success": true,
  "message": "User retrieved",
  "data": {
    "_id": "507f1f77bcf86cd799439011",
    "name": "Deepak Kumar",
    "email": "deepak@example.com",
    "role": "user"
  }
}
```

#### Logout
```http
POST /auth/logout
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200):**
```json
{
  "success": true,
  "message": "Logged out successfully",
  "data": null
}
```

### OAuth Routes

#### Google OAuth
```http
GET /auth/google
# Redirects to Google OAuth consent screen
```

```http
GET /auth/google/callback
# Google redirects here after authentication
```

#### GitHub OAuth
```http
GET /auth/github
# Redirects to GitHub OAuth authorization
```

```http
GET /auth/github/callback
# GitHub redirects here after authentication
```

---

## Advanced Usage

### Custom Configuration

```typescript
import { config } from 'campusauth';

// Update configuration at runtime
config.set({
  jwtSecret: 'custom-secret-key',
  jwtExpiresIn: '2h',
  jwtRefreshExpiresIn: '14d',
});

// Get configuration
const jwtSecret = config.get('jwtSecret');
const allConfig = config.get();
```

### Manual Token Management

```typescript
import { generateTokenPair, verifyToken, verifyRefreshToken } from 'campusauth';

// Generate token pair
const tokens = generateTokenPair({
  id: user._id.toString(),
  email: user.email,
  role: user.role,
});

// Verify access token
try {
  const decoded = verifyToken(tokens.accessToken);
  console.log('User ID:', decoded.id);
} catch (error) {
  console.error('Invalid token');
}

// Verify refresh token
try {
  const decoded = verifyRefreshToken(tokens.refreshToken);
  console.log('Token valid for user:', decoded.id);
} catch (error) {
  console.error('Invalid refresh token');
}
```

### Custom Error Handling

```typescript
import { AppError, asyncHandler } from 'campusauth';

// Throw custom errors
app.get('/custom', asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);
  
  if (!user) {
    throw new AppError('User not found', 404);
  }
  
  res.json({ user });
}));

// Async route handler with automatic error catching
app.post('/users', asyncHandler(async (req, res) => {
  const user = await User.create(req.body);
  res.status(201).json({ user });
}));
```

### Password Utilities

```typescript
import { hashPassword, verifyPassword } from 'campusauth';

// Hash password
const hashedPassword = await hashPassword('mySecurePassword123');

// Verify password
const isValid = await verifyPassword('mySecurePassword123', hashedPassword);
console.log('Password valid:', isValid);
```

### Validation Utilities

```typescript
import { ValidationUtil } from 'campusauth';

// Email validation
const isValidEmail = ValidationUtil.isEmail('deepak@example.com');

// Password strength validation
const passwordCheck = ValidationUtil.isStrongPassword('MyPass123');
if (!passwordCheck.valid) {
  console.log('Password error:', passwordCheck.message);
}

// Required fields validation
const validation = ValidationUtil.validateRequiredFields(
  req.body, 
  ['name', 'email', 'password']
);
if (!validation.valid) {
  console.log('Missing fields:', validation.missing);
}

// Sanitize user input
const cleanInput = ValidationUtil.sanitizeInput(req.body.name);
```

### Custom Logging

```typescript
import { logger } from 'campusauth';

logger.info('User registered successfully');
logger.warn('Deprecated API endpoint used');
logger.error('Database connection failed', error);
logger.debug('Debug information', { userId: 123 });
```

### Direct Database Access

```typescript
import { User, connectDB } from 'campusauth';

await connectDB(process.env.MONGO_URI!);

// Find user
const user = await User.findOne({ email: 'deepak@example.com' });

// Update user role
await User.findByIdAndUpdate(userId, { role: 'admin' });

// Delete user
await User.findByIdAndDelete(userId);

// Count users
const userCount = await User.countDocuments({ provider: 'local' });
```

---

## TypeScript Support

Full TypeScript support with comprehensive type definitions:

```typescript
import type {
  IUser,
  JWTPayload,
  AuthRequest,
  AuthNextApiRequest,
  TokenPair,
  CampusAuthConfig,
  ApiResponse,
  OAuthConfig,
} from 'campusauth';

// Use in your code
const user: IUser = {
  name: 'Deepak Kumar',
  email: 'deepak@example.com',
  role: 'user',
  provider: 'local',
};

// Type-safe request handlers
app.get('/profile', protect(), (req: AuthRequest, res: Response) => {
  const user: IUser = req.user!;
  res.json({ user });
});
```

---

## Error Handling

CampusAuth provides comprehensive error handling:

### Error Response Format

```json
{
  "success": false,
  "error": "Error message here"
}
```

### Common Error Codes

| Status Code | Error | Description |
|-------------|-------|-------------|
| 400 | Bad Request | Invalid request data or validation failed |
| 401 | Unauthorized | Missing or invalid authentication token |
| 403 | Forbidden | Insufficient permissions for the resource |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Duplicate entry (e.g., email already exists) |
| 500 | Internal Server Error | Server-side error |

### Handling Errors in Client

```typescript
try {
  const response = await fetch('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  
  const data = await response.json();
  
  if (!data.success) {
    console.error('Login failed:', data.error);
  } else {
    console.log('Login successful:', data.data);
  }
} catch (error) {
  console.error('Network error:', error);
}
```

---

## Testing

### Setup Test Environment

Create `.env.test`:

```bash
MONGO_URI=mongodb://localhost:27017/campusauth-test
JWT_SECRET=test-secret-key-min-32-characters-long
JWT_REFRESH_SECRET=test-refresh-secret-key-min-32-characters
```

### Example Test (Jest)

```typescript
import request from 'supertest';
import app from './app';
import { connectDB, disconnectDB } from 'campusauth';

beforeAll(async () => {
  await connectDB(process.env.MONGO_URI!);
});

afterAll(async () => {
  await disconnectDB();
});

describe('Authentication', () => {
  test('should register new user', async () => {
    const response = await request(app)
      .post('/auth/register')
      .send({
        name: 'Test User',
        email: 'test@example.com',
        password: 'TestPass123',
      });
    
    expect(response.status).toBe(201);
    expect(response.body.success).toBe(true);
    expect(response.body.data.user.email).toBe('test@example.com');
  });
});
```

---

## Production Deployment

### MERN Stack Deployment

#### Backend Deployment (Express.js)

**Heroku Deployment:**
```bash
# In backend directory
echo "node_modules\n.env" > .gitignore
git init
git add .
git commit -m "Initial commit"
heroku create your-app-name-backend
heroku config:set MONGO_URI=your-production-mongodb-uri
heroku config:set JWT_SECRET=your-production-jwt-secret
git push heroku main
```

**Environment Variables for Production:**
```bash
NODE_ENV=production
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/production
JWT_SECRET=your-production-jwt-secret-64-characters-long
CORS_ORIGIN=https://your-frontend-domain.com
```

#### Frontend Deployment (React/Next.js)

**Vercel Deployment:**
```bash
# In frontend directory
npm install -g vercel
vercel --prod
```

Set environment variables in Vercel dashboard:
```bash
NEXT_PUBLIC_API_URL=https://your-backend-domain.herokuapp.com/api
```

### Next.js Full-Stack Deployment

**Vercel Deployment:**
1. Connect your GitHub repository to Vercel
2. Set environment variables in Vercel dashboard
3. Deploy automatically on git push

**Environment Variables:**
```bash
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/production
JWT_SECRET=your-production-secret-64-characters
NEXTAUTH_URL=https://your-domain.vercel.app
```

---

## Troubleshooting

### Next.js Specific Issues

**Issue: OAuth Callbacks Not Working**
```
Solution: Ensure callback URLs in OAuth provider settings match your deployment URL
- Development: http://localhost:3000/api/auth/oauth/[provider]/callback
- Production: https://yourdomain.com/api/auth/oauth/[provider]/callback
```

**Issue: Middleware Not Working**
```
Solution: Ensure middleware.ts is in project root and uses correct configuration
```

**Issue: API Routes Not Found**
```
Solution: Check file structure in pages/api/auth/ directory matches the routing pattern
```

**Issue: Database Connection Issues**
```
Solution: Ensure MONGO_URI is set in .env.local and MongoDB is accessible
```

---

## Contributing

We welcome contributions! Here's how you can help:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/deepakkumar55/campusauth.git
cd campusauth
npm install
npm run dev
```

---

## License

MIT License - see LICENSE file for details

---

## Support & Contact

- **Email**: deepak@thecampuscoders.com
- **Issues**: [GitHub Issues](https://github.com/deepakkumar55/campusauth/issues)
- **Documentation**: [campusauth.d3vv.tech](https://campusauth.d3vv.tech)
- **Author**: Deepak Kumar

---

## Changelog

### Version 1.2.0 (Current)

- Added MERN stack backend setup
- Added Next.js App Router support
- Full-stack Next.js integration
- JWT authentication with refresh tokens
- Role-based access control (RBAC)
- OAuth integration (Google, GitHub)
- Express.js middleware
- TypeScript support
- Comprehensive error handling
- Input validation utilities
- MongoDB integration

---

**Built with precision for developers who value security and simplicity**
