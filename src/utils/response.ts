import { Response } from 'express';
import { ApiResponse } from '../types';

export class ResponseUtil {
  static success<T>(res: Response, data: T, message = 'Success', statusCode = 200): Response {
    const response: ApiResponse<T> = {
      success: true,
      message,
      data,
    };
    return res.status(statusCode).json(response);
  }

  static error(res: Response, error: string, statusCode = 400): Response {
    const response: ApiResponse = {
      success: false,
      error,
    };
    return res.status(statusCode).json(response);
  }

  static unauthorized(res: Response, message = 'Unauthorized'): Response {
    return ResponseUtil.error(res, message, 401);
  }

  static forbidden(res: Response, message = 'Access Denied'): Response {
    return ResponseUtil.error(res, message, 403);
  }

  static notFound(res: Response, message = 'Resource not found'): Response {
    return ResponseUtil.error(res, message, 404);
  }

  static serverError(res: Response, message = 'Internal server error'): Response {
    return ResponseUtil.error(res, message, 500);
  }
}
