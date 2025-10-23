import jwt from 'jsonwebtoken';
import { JWTPayload, TokenPair } from '../types';
import { config } from '../config/config';
import { logger } from '../utils/logger';

export const generateToken = (
  payload: JWTPayload,
  secret?: string,
  expiresIn?: string
): string => {
  try {
    const jwtSecret = secret || config.get('jwtSecret');
    const expiry = expiresIn || config.get('jwtExpiresIn');
    
    if (!jwtSecret) {
      throw new Error('JWT secret is required');
    }

    // Add issued at time
    const tokenPayload = {
      ...payload,
      iat: Math.floor(Date.now() / 1000),
    };

    // Ensure types align with jsonwebtoken TypeScript definitions
    const secretValue = jwtSecret as jwt.Secret;
    const expiresInValue = expiry as jwt.SignOptions['expiresIn'];

    return jwt.sign(tokenPayload, secretValue, { expiresIn: expiresInValue });
  } catch (error) {
    logger.error('Error generating token:', error);
    throw new Error('Failed to generate token');
  }
};

export const generateRefreshToken = (payload: JWTPayload): string => {
  try {
    const refreshSecret = config.get('jwtRefreshSecret');
    const expiry = config.get('jwtRefreshExpiresIn');
    
    if (!refreshSecret) {
      throw new Error('JWT refresh secret is required');
    }

    // Add issued at time and mark as refresh token
    const tokenPayload = {
      ...payload,
      type: 'refresh',
      iat: Math.floor(Date.now() / 1000),
    };

    // Ensure types align with jsonwebtoken TypeScript definitions
    const secretValue = refreshSecret as jwt.Secret;
    const expiresInValue = expiry as jwt.SignOptions['expiresIn'];

    return jwt.sign(tokenPayload, secretValue, { expiresIn: expiresInValue });
  } catch (error) {
    logger.error('Error generating refresh token:', error);
    throw new Error('Failed to generate refresh token');
  }
};

export const generateTokenPair = (payload: JWTPayload): TokenPair => {
  try {
    return {
      accessToken: generateToken(payload),
      refreshToken: generateRefreshToken(payload),
    };
  } catch (error) {
    logger.error('Error generating token pair:', error);
    throw new Error('Failed to generate token pair');
  }
};

export const verifyToken = (token: string, secret?: string): JWTPayload => {
  try {
    if (!token) {
      throw new Error('Token is required');
    }

    const jwtSecret = secret || config.get('jwtSecret');
    
    if (!jwtSecret) {
      throw new Error('JWT secret is required');
    }

    const decoded = jwt.verify(token, jwtSecret) as JWTPayload;
    
    // Validate token structure
    if (!decoded.id) {
      throw new Error('Invalid token structure');
    }

    return decoded;
  } catch (error: any) {
    if (error.name === 'TokenExpiredError') {
      throw new Error('Token expired');
    } else if (error.name === 'JsonWebTokenError') {
      throw new Error('Invalid token');
    } else if (error.name === 'NotBeforeError') {
      throw new Error('Token not active');
    }
    
    logger.error('Token verification error:', error);
    throw error;
  }
};

export const verifyRefreshToken = (token: string): JWTPayload => {
  try {
    if (!token) {
      throw new Error('Refresh token is required');
    }

    const refreshSecret = config.get('jwtRefreshSecret');
    
    if (!refreshSecret) {
      throw new Error('JWT refresh secret is required');
    }

    const decoded = jwt.verify(token, refreshSecret) as JWTPayload & { type?: string };
    
    // Validate token structure and type
    if (!decoded.id || decoded.type !== 'refresh') {
      throw new Error('Invalid refresh token structure');
    }

    // Remove type field before returning
    const { type, ...payload } = decoded;
    return payload;
  } catch (error: any) {
    if (error.name === 'TokenExpiredError') {
      throw new Error('Refresh token expired');
    } else if (error.name === 'JsonWebTokenError') {
      throw new Error('Invalid refresh token');
    } else if (error.name === 'NotBeforeError') {
      throw new Error('Refresh token not active');
    }
    
    logger.error('Refresh token verification error:', error);
    throw error;
  }
};

export const decodeToken = (token: string): JWTPayload | null => {
  try {
    if (!token) return null;
    return jwt.decode(token) as JWTPayload | null;
  } catch (error) {
    logger.error('Token decode error:', error);
    return null;
  }
};

// Utility to get token expiration time
export const getTokenExpiration = (token: string): Date | null => {
  try {
    const decoded = decodeToken(token);
    if (decoded && decoded.exp) {
      return new Date(decoded.exp * 1000);
    }
    return null;
  } catch {
    return null;
  }
};

// Utility to check if token is expired
export const isTokenExpired = (token: string): boolean => {
  try {
    const expiration = getTokenExpiration(token);
    if (!expiration) return true;
    return expiration.getTime() < Date.now();
  } catch {
    return true;
  }
};
