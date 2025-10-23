import jwt from 'jsonwebtoken';
import { JWTPayload, TokenPair } from '../types';
import { config } from '../config/config';

export const generateToken = (
  payload: JWTPayload,
  secret?: string,
  expiresIn?: string
): string => {
  const jwtSecret = secret || config.get('jwtSecret');
  const expiry = expiresIn || config.get('jwtExpiresIn');
  return jwt.sign(payload, jwtSecret, { expiresIn: expiry });
};

export const generateRefreshToken = (payload: JWTPayload): string => {
  const refreshSecret = config.get('jwtRefreshSecret');
  const expiry = config.get('jwtRefreshExpiresIn');
  return jwt.sign(payload, refreshSecret, { expiresIn: expiry });
};

export const generateTokenPair = (payload: JWTPayload): TokenPair => {
  return {
    accessToken: generateToken(payload),
    refreshToken: generateRefreshToken(payload),
  };
};

export const verifyToken = (token: string, secret?: string): JWTPayload => {
  const jwtSecret = secret || config.get('jwtSecret');
  return jwt.verify(token, jwtSecret) as JWTPayload;
};

export const verifyRefreshToken = (token: string): JWTPayload => {
  const refreshSecret = config.get('jwtRefreshSecret');
  return jwt.verify(token, refreshSecret) as JWTPayload;
};

export const decodeToken = (token: string): JWTPayload | null => {
  return jwt.decode(token) as JWTPayload | null;
};
