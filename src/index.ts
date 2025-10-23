// Core
export { connectDB, disconnectDB } from './utils/db';
export { generateToken, verifyToken, generateRefreshToken, generateTokenPair, verifyRefreshToken } from './core/jwt';
export { hashPassword, verifyPassword } from './core/hash';
export { User } from './core/userModel';
export { setupOAuth } from './core/oauth';

// Middleware
export { protect } from './middleware/protect';
export { allowRoles, requireRole, requireAdmin, requireModerator } from './middleware/roles';
export { errorHandler, asyncHandler, AppError } from './middleware/errorHandler';

// Routes
export { default as authRoutes } from './routes/authRoutes';
export { default as oauthRoutes } from './routes/oauthRoutes';

// Next.js
export { withAuth, withRoles } from './next/withAuth';
export { createAuthMiddleware } from './next/middleware';
export type { AuthNextApiRequest } from './next/withAuth';

// Utils
export { logger } from './utils/logger';
export { ResponseUtil } from './utils/response';
export { ValidationUtil } from './utils/validation';
export { config } from './config/config';

// Types
export type {
  IUser,
  JWTPayload,
  AuthRequest,
  AuthMiddleware,
  TokenPair,
  OAuthConfig,
  CampusAuthConfig,
  ApiResponse,
} from './types';
