import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { ResponseUtil } from '../utils/response';

export class AppError extends Error {
  statusCode: number;
  isOperational: boolean;

  constructor(message: string, statusCode: number) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

export const errorHandler = (
  err: Error | AppError,
  _req: Request,
  res: Response,
  _next: NextFunction
): Response => {
  logger.error('Error:', err);

  if (err instanceof AppError) {
    return ResponseUtil.error(res, err.message, err.statusCode);
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    return ResponseUtil.error(res, 'Validation failed', 400);
  }

  // Mongoose duplicate key error
  if (err.name === 'MongoServerError' && (err as any).code === 11000) {
    return ResponseUtil.error(res, 'Duplicate entry', 409);
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return ResponseUtil.unauthorized(res, 'Invalid token');
  }

  if (err.name === 'TokenExpiredError') {
    return ResponseUtil.unauthorized(res, 'Token expired');
  }

  // Default error
  return ResponseUtil.serverError(res, 'Something went wrong');
};

export const asyncHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};
