import { Response, NextFunction } from 'express';
import { verifyToken } from '../core/jwt';
import { User } from '../core/userModel';
import { AuthRequest } from '../types';
import { ResponseUtil } from '../utils/response';
import { logger } from '../utils/logger';

export const protect = () => async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void | Response> => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return ResponseUtil.unauthorized(res, 'No token provided');
    }

    const token = authHeader.split(' ')[1];

    if (!token) {
      return ResponseUtil.unauthorized(res, 'No token provided');
    }

    const decoded = verifyToken(token);

    const user = await User.findById(decoded.id).select('-password -refreshToken');

    if (!user) {
      return ResponseUtil.unauthorized(res, 'User not found');
    }

    req.user = user.toJSON();
    next();
  } catch (error: any) {
    logger.error('Auth middleware error:', error);
    
    if (error.name === 'TokenExpiredError') {
      return ResponseUtil.unauthorized(res, 'Token expired');
    }
    
    if (error.name === 'JsonWebTokenError') {
      return ResponseUtil.unauthorized(res, 'Invalid token');
    }

    return ResponseUtil.unauthorized(res, 'Authentication failed');
  }
};
