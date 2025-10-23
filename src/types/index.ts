import { Request, Response, NextFunction } from 'express';

export interface IUser {
  _id?: string;
  name: string;
  email: string;
  password?: string;
  provider?: string;
  role: string;
  refreshToken?: string;
  createdAt?: Date;
  updatedAt?: Date;
}

export interface JWTPayload {
  id: string;
  email?: string;
  role?: string;
}

export interface AuthRequest extends Request {
  user?: IUser;
}

export type AuthMiddleware = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => Promise<void> | void;

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface OAuthConfig {
  google?: {
    clientId: string;
    clientSecret: string;
    callbackURL: string;
  };
  github?: {
    clientId: string;
    clientSecret: string;
    callbackURL: string;
  };
  linkedin?: {
    clientId: string;
    clientSecret: string;
    callbackURL: string;
  };
}

export interface CampusAuthConfig {
  jwtSecret: string;
  jwtRefreshSecret?: string;
  jwtExpiresIn?: string;
  jwtRefreshExpiresIn?: string;
  mongoUri?: string;
  oauth?: OAuthConfig;
}

export interface ApiResponse<T = any> {
  success: boolean;
  message?: string;
  data?: T;
  error?: string;
}
