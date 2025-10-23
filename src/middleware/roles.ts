import { Response, NextFunction } from 'express';
import { AuthRequest } from '../types';
import { ResponseUtil } from '../utils/response';

export const allowRoles = (...roles: string[]) => (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void | Response => {
  if (!req.user) {
    return ResponseUtil.unauthorized(res, 'Authentication required');
  }

  if (!roles.includes(req.user.role)) {
    return ResponseUtil.forbidden(
      res,
      `Access denied. Required roles: ${roles.join(', ')}`
    );
  }

  next();
};

export const requireRole = (role: string) => allowRoles(role);

export const requireAdmin = () => allowRoles('admin');

export const requireModerator = () => allowRoles('admin', 'moderator');
