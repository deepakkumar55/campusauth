import { Request, Response, NextFunction } from 'express';

export interface IUser {
  _id?: string;
  name: string;
  email: string;
  password?: string;
  provider?: 'local' | 'google' | 'github' | 'linkedin';
  role: 'user' | 'admin' | 'moderator';
  refreshToken?: string;
  createdAt?: Date;
  updatedAt?: Date;
  toJSON?: () => any;
}

export interface JWTPayload {
  id: string;
  email?: string;
  role?: string;
  iat?: number;
  exp?: number;
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

export interface ValidationResult {
  valid: boolean;
  message?: string;
  missing?: string[];
}

export interface AuthContextType {
  user: IUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<{ success: boolean; error?: string }>;
  register: (name: string, email: string, password: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => Promise<void>;
  refreshToken: () => Promise<boolean>;
}
