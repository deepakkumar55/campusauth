import { NextApiRequest, NextApiResponse } from 'next';
import { verifyToken } from '../core/jwt';
import { User } from '../core/userModel';
import { ResponseUtil } from '../utils/response';
import { logger } from '../utils/logger';

export interface AuthNextApiRequest extends NextApiRequest {
  user?: any;
}

export const withAuth = (handler: (req: AuthNextApiRequest, res: NextApiResponse) => Promise<void>) => {
  return async (req: AuthNextApiRequest, res: NextApiResponse): Promise<void> => {
    try {
      const authHeader = req.headers.authorization as string;

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided' });
      }

      const token = authHeader.split(' ')[1];

      if (!token) {
        ResponseUtil.unauthorized(res as any, 'No token provided');
        return;
      }

      const decoded = verifyToken(token);

      const user = await User.findById(decoded.id).select('-password -refreshToken');

      if (!user) {
        return res.status(401).json({ error: 'User not found' });
      }

      req.user = user.toJSON();
      return handler(req, res);
    } catch (error: any) {
      logger.error('Next.js auth error:', error);

      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Token expired' });
      }

      if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({ error: 'Invalid token' });
      }

      return res.status(401).json({ error: 'Authentication failed' });
    }
  };
};

export const withRoles = (roles: string[], handler: (req: AuthNextApiRequest, res: NextApiResponse) => Promise<void>) => {
  return withAuth(async (req: AuthNextApiRequest, res: NextApiResponse) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: `Access denied. Required roles: ${roles.join(', ')}` });
    }
    return handler(req, res);
  });
};
