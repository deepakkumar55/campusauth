import express from 'express';
import { User } from '../core/userModel';
import { hashPassword, verifyPassword } from '../core/hash';
import { generateTokenPair, verifyRefreshToken } from '../core/jwt';
import { ValidationUtil } from '../utils/validation';
import { ResponseUtil } from '../utils/response';
import { asyncHandler, AppError } from '../middleware/errorHandler';
import { protect } from '../middleware/protect';
import { logger } from '../utils/logger';

const router = express.Router();

// Register new user
router.post('/register', asyncHandler(async (req: any, res: any) => {
  const { name, email, password } = req.body;

  // Validate required fields
  const validation = ValidationUtil.validateRequiredFields(req.body, ['name', 'email', 'password']);
  if (!validation.valid) {
    throw new AppError(`Missing fields: ${validation.missing?.join(', ')}`, 400);
  }

  // Validate email format
  if (!ValidationUtil.isEmail(email)) {
    throw new AppError('Invalid email format', 400);
  }

  // Validate password strength
  const passwordValidation = ValidationUtil.isStrongPassword(password);
  if (!passwordValidation.valid) {
    throw new AppError(passwordValidation.message!, 400);
  }

  // Check if user already exists
  const existing = await User.findOne({ email: email.toLowerCase() });
  if (existing) {
    throw new AppError('User already exists with this email', 409);
  }

  // Create user
  const hashedPassword = await hashPassword(password);
  const user = await User.create({
    name: ValidationUtil.sanitizeName(name),
    email: email.toLowerCase(),
    password: hashedPassword,
    provider: 'local',
    role: 'user',
  });

  // Generate tokens
  const tokens = generateTokenPair({ 
    id: user._id!.toString(), 
    email: user.email,
    role: user.role 
  });

  // Save refresh token
  user.refreshToken = tokens.refreshToken;
  await user.save();

  logger.info(`New user registered: ${user.email}`);

  return ResponseUtil.success(
    res,
    {
      user: user.toJSON(),
      ...tokens,
    },
    'Registration successful',
    201
  );
}));

// Login user
router.post('/login', asyncHandler(async (req: any, res: any) => {
  const { email, password } = req.body;

  // Validate required fields
  const validation = ValidationUtil.validateRequiredFields(req.body, ['email', 'password']);
  if (!validation.valid) {
    throw new AppError(`Missing fields: ${validation.missing?.join(', ')}`, 400);
  }

  // Validate email format
  if (!ValidationUtil.isEmail(email)) {
    throw new AppError('Invalid email format', 400);
  }

  // Find user
  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user || !user.password) {
    throw new AppError('Invalid credentials', 401);
  }

  // Verify password
  const isValid = await verifyPassword(password, user.password);
  if (!isValid) {
    throw new AppError('Invalid credentials', 401);
  }

  // Generate tokens
  const tokens = generateTokenPair({ 
    id: user._id!.toString(), 
    email: user.email, 
    role: user.role 
  });

  // Save refresh token
  user.refreshToken = tokens.refreshToken;
  await user.save();

  logger.info(`User logged in: ${user.email}`);

  return ResponseUtil.success(res, {
    user: user.toJSON(),
    ...tokens,
  }, 'Login successful');
}));

// Refresh token
router.post('/refresh', asyncHandler(async (req: any, res: any) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    throw new AppError('Refresh token required', 400);
  }

  try {
    // Verify refresh token
    const decoded = verifyRefreshToken(refreshToken);

    // Find user and verify refresh token matches
    const user = await User.findById(decoded.id);
    if (!user || user.refreshToken !== refreshToken) {
      throw new AppError('Invalid refresh token', 401);
    }

    // Generate new tokens
    const tokens = generateTokenPair({ 
      id: user._id!.toString(), 
      email: user.email, 
      role: user.role 
    });

    // Update refresh token
    user.refreshToken = tokens.refreshToken;
    await user.save();

    logger.info(`Token refreshed for user: ${user.email}`);

    return ResponseUtil.success(res, tokens, 'Token refreshed');
  } catch (error: any) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      throw new AppError('Invalid refresh token', 401);
    }
    throw error;
  }
}));

// Logout user
router.post('/logout', protect() as unknown as express.RequestHandler, asyncHandler(async (req: any, res: any) => {
  try {
    const user = await User.findById(req.user._id);
    if (user) {
      user.refreshToken = undefined;
      await user.save();
      logger.info(`User logged out: ${user.email}`);
    }

    return ResponseUtil.success(res, null, 'Logged out successfully');
  } catch (error) {
    logger.error('Logout error:', error);
    return ResponseUtil.success(res, null, 'Logged out successfully');
  }
}));

// Get current user
router.get('/me', protect() as unknown as express.RequestHandler, asyncHandler(async (req: any, res: any) => {
  return ResponseUtil.success(res, req.user, 'User retrieved');
}));

// Update user profile
router.put('/profile', protect() as unknown as express.RequestHandler, asyncHandler(async (req: any, res: any) => {
  const { name } = req.body;

  if (!name || typeof name !== 'string' || !name.trim()) {
    throw new AppError('Name is required', 400);
  }

  const user = await User.findByIdAndUpdate(
    req.user._id,
    { name: ValidationUtil.sanitizeName(name) },
    { new: true, runValidators: true }
  ).select('-password -refreshToken');

  if (!user) {
    throw new AppError('User not found', 404);
  }

  logger.info(`Profile updated for user: ${user.email}`);

  return ResponseUtil.success(res, user.toJSON(), 'Profile updated successfully');
}));

export default router;
