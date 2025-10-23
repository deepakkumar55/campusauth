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
- **Next.js Middleware** — Protect API routes & pages seamlessly  
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

## Complete Setup Guide

### Prerequisites

Before you begin, ensure you have the following installed:
- Node.js (v16 or higher)
- MongoDB (local or cloud instance)
- npm or yarn package manager

### Step 1: Install CampusAuth

```bash
npm install campusauth mongoose express passport bcrypt jsonwebtoken
```

For TypeScript projects, also install:

```bash
npm install -D typescript @types/node @types/express @types/passport
```

### Step 2: Environment Configuration

Create a `.env` file in your project root:

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
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback

# GitHub OAuth (Optional)
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_CALLBACK_URL=http://localhost:3000/auth/github/callback

# Server Configuration
PORT=3000
NODE_ENV=development
```

**Important Security Notes:**
- Never commit `.env` file to version control
- Use strong, random secrets for JWT (minimum 32 characters)
- Change default secrets in production
- Use environment-specific `.env` files

### Step 3: Generate Strong Secrets

You can generate strong secrets using Node.js:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Step 4: Setup OAuth Providers (Optional)

#### Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client IDs"
5. Set authorized redirect URIs:
   - `http://localhost:3000/auth/google/callback` (development)
   - `https://yourdomain.com/auth/google/callback` (production)
6. Copy Client ID and Client Secret to `.env`

#### GitHub OAuth Setup

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in application details:
   - Homepage URL: `http://localhost:3000`
   - Authorization callback URL: `http://localhost:3000/auth/github/callback`
4. Copy Client ID and Client Secret to `.env`

---

## Quick Start

### Express.js Setup

Create `server.js` or `app.ts`:

```typescript
import express from 'express';
import passport from 'passport';
import dotenv from 'dotenv';
import {
  connectDB,
  setupOAuth,
  authRoutes,
  oauthRoutes,
  errorHandler,
} from 'campusauth';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize database connection
async function startServer() {
  try {
    // Connect to MongoDB
    await connectDB(process.env.MONGO_URI!);

    // Setup OAuth providers (if credentials provided)
    setupOAuth();

    // Middleware
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use(passport.initialize());

    // Health check route
    app.get('/', (req, res) => {
      res.json({ message: 'CampusAuth API is running' });
    });

    // Authentication routes
    app.use('/auth', authRoutes);
    app.use('/auth', oauthRoutes);

    // Error handler (must be last)
    app.use(errorHandler);

    app.listen(PORT, () => {
      console.log(`Server is running on http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();
```

Run your server:

```bash
node server.js
# or for TypeScript
ts-node server.ts
# or with nodemon
nodemon server.js
```

---

## Protecting Routes

### Express.js Routes Protection

```typescript
import { protect, allowRoles, requireAdmin, requireModerator } from 'campusauth';

// Public route
app.get('/public', (req, res) => {
  res.json({ message: 'Public endpoint' });
});

// Protected route (requires authentication)
app.get('/profile', protect(), (req, res) => {
  res.json({ 
    message: 'User profile',
    user: req.user 
  });
});

// Admin only route
app.get('/admin/dashboard', protect(), requireAdmin(), (req, res) => {
  res.json({ message: 'Admin dashboard' });
});

// Multiple roles allowed
app.get('/moderator/panel', protect(), requireModerator(), (req, res) => {
  res.json({ message: 'Moderator panel' });
});

// Custom roles
app.get('/custom', protect(), allowRoles('admin', 'moderator', 'editor'), (req, res) => {
  res.json({ message: 'Custom role access' });
});
```

---

## Next.js Integration

### API Routes Protection

Create `pages/api/profile.ts`:

```typescript
import { withAuth, connectDB } from 'campusauth';

// Initialize DB connection once
let isConnected = false;

async function handler(req: any, res: any) {
  if (!isConnected) {
    await connectDB(process.env.MONGO_URI!);
    isConnected = true;
  }

  if (req.method === 'GET') {
    res.status(200).json({ 
      success: true,
      user: req.user 
    });
  } else {
    res.status(405).json({ error: 'Method not allowed' });
  }
}

export default withAuth(handler);
```

### Role-Based API Routes

Create `pages/api/admin/users.ts`:

```typescript
import { withRoles, connectDB } from 'campusauth';

let isConnected = false;

async function handler(req: any, res: any) {
  if (!isConnected) {
    await connectDB(process.env.MONGO_URI!);
    isConnected = true;
  }

  // Only admin can access this route
  res.status(200).json({ 
    message: 'Admin users list',
    user: req.user 
  });
}

export default withRoles(['admin'], handler);
```

### Next.js Middleware (App Router)

Create `middleware.ts` in your project root:

```typescript
import { createAuthMiddleware } from 'campusauth';

export const middleware = createAuthMiddleware({
  protectedPaths: ['/dashboard', '/profile', '/admin', '/settings'],
  publicPaths: ['/login', '/register', '/', '/about'],
  loginPath: '/login',
});

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};
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

### Environment Variables Checklist

- [ ] Strong JWT_SECRET (32+ characters)
- [ ] Strong JWT_REFRESH_SECRET (32+ characters)
- [ ] Production MongoDB URI
- [ ] OAuth credentials (if using)
- [ ] NODE_ENV=production
- [ ] Proper CORS configuration
- [ ] Rate limiting enabled
- [ ] HTTPS enforced

### Security Best Practices

1. **Use HTTPS**: Always use HTTPS in production
2. **Environment Variables**: Never commit `.env` files
3. **Rate Limiting**: Implement rate limiting on auth endpoints
4. **CORS**: Configure CORS properly
5. **Helmet**: Use helmet.js for security headers
6. **Token Expiry**: Keep access token expiry short (1h recommended)
7. **Password Policy**: Enforce strong passwords
8. **Input Validation**: Always validate and sanitize user input

### Example Production Setup

```typescript
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true,
}));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per window
  message: 'Too many attempts, please try again later',
});

app.use('/auth/login', authLimiter);
app.use('/auth/register', authLimiter);
```

---

## Troubleshooting

### Common Issues

**Issue: MongoDB Connection Failed**
```
Solution: Check MONGO_URI in .env file and ensure MongoDB is running
```

**Issue: JWT Token Invalid**
```
Solution: Ensure JWT_SECRET matches between token generation and verification
```

**Issue: OAuth Callback Error**
```
Solution: Verify callback URLs match in OAuth provider settings and .env file
```

**Issue: TypeScript Errors**
```
Solution: Install required type definitions:
npm install -D @types/express @types/passport @types/node
```

---

## Migration Guide

### From v0.x to v1.0

Version 1.0 includes breaking changes:

1. **JWT Configuration**: Now uses config singleton
   ```typescript
   // Old
   generateToken(payload, process.env.JWT_SECRET)
   
   // New
   generateToken(payload) // Uses config automatically
   ```

2. **Error Handling**: New error handler middleware required
   ```typescript
   import { errorHandler } from 'campusauth';
   app.use(errorHandler); // Must be last middleware
   ```

3. **Response Format**: Standardized API responses
   ```typescript
   // All responses now follow { success, message, data, error } format
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

### Version 1.1.2 (Current)

- Initial release
- JWT authentication with refresh tokens
- Role-based access control (RBAC)
- OAuth integration (Google, GitHub)
- Express.js middleware
- Next.js API routes protection
- TypeScript support
- Comprehensive error handling
- Input validation utilities
- MongoDB integration

---

**Built with precision for developers who value security and simplicity**
