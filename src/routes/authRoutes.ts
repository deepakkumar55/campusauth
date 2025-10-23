import express from 'express';
import { User } from '../core/userModel';
import { hashPassword, verifyPassword } from '../core/hash';
import { generateTokenPair, verifyRefreshToken } from '../core/jwt';
import { ValidationUtil } from '../utils/validation';
import { ResponseUtil } from '../utils/response';
import { asyncHandler } from '../middleware/errorHandler';
import { protect } from '../middleware/protect';

const router = express.Router();

router.post('/register', asyncHandler(async (req: any, res: any) => {
  const { name, email, password } = req.body;

  // Validate required fields
  const validation = ValidationUtil.validateRequiredFields(req.body, ['name', 'email', 'password']);
  if (!validation.valid) {
    return ResponseUtil.error(res, `Missing fields: ${validation.missing?.join(', ')}`, 400);
  }

  // Validate email
  if (!ValidationUtil.isEmail(email)) {
    return ResponseUtil.error(res, 'Invalid email format', 400);
  }

  // Validate password strength
  const passwordValidation = ValidationUtil.isStrongPassword(password);
  if (!passwordValidation.valid) {
    return ResponseUtil.error(res, passwordValidation.message!, 400);
  }

  // Check if user exists
  const existing = await User.findOne({ email: email.toLowerCase() });
  if (existing) {
    return ResponseUtil.error(res, 'User already exists', 409);
  }

  // Create user
  const hashedPassword = await hashPassword(password);
  const user = await User.create({
    name: ValidationUtil.sanitizeInput(name),
    email: email.toLowerCase(),
    password: hashedPassword,
    provider: 'local',
  });

  // Generate tokens
  const tokens = generateTokenPair({ id: user._id!.toString(), email: user.email });

  // Save refresh token
  user.refreshToken = tokens.refreshToken;
  await user.save();

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

router.post('/login', asyncHandler(async (req: any, res: any) => {
  const { email, password } = req.body;

  // Validate required fields
  const validation = ValidationUtil.validateRequiredFields(req.body, ['email', 'password']);
  if (!validation.valid) {
    return ResponseUtil.error(res, `Missing fields: ${validation.missing?.join(', ')}`, 400);
  }

  // Find user
  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user || !user.password) {
    return ResponseUtil.unauthorized(res, 'Invalid credentials');
  }

  // Verify password
  const isValid = await verifyPassword(password, user.password);
  if (!isValid) {
    return ResponseUtil.unauthorized(res, 'Invalid credentials');
  }

  // Generate tokens
  const tokens = generateTokenPair({ id: user._id!.toString(), email: user.email, role: user.role });

  // Save refresh token
  user.refreshToken = tokens.refreshToken;
  await user.save();

  return ResponseUtil.success(res, {
    user: user.toJSON(),
    ...tokens,
  }, 'Login successful');
}));

router.post('/refresh', asyncHandler(async (req: any, res: any) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return ResponseUtil.error(res, 'Refresh token required', 400);
  }

  // Verify refresh token
  const decoded = verifyRefreshToken(refreshToken);

  // Find user and verify refresh token matches
  const user = await User.findById(decoded.id);
  if (!user || user.refreshToken !== refreshToken) {
    return ResponseUtil.unauthorized(res, 'Invalid refresh token');
  }

  // Generate new tokens
  const tokens = generateTokenPair({ id: user._id!.toString(), email: user.email, role: user.role });

  // Update refresh token
  user.refreshToken = tokens.refreshToken;
  await user.save();

  return ResponseUtil.success(res, tokens, 'Token refreshed');
}));

router.post('/logout', protect() as any, asyncHandler(async (req: any, res: any) => {
  const user = await User.findById(req.user._id);
  if (user) {
    user.refreshToken = undefined;
    await user.save();
  }

  return ResponseUtil.success(res, null, 'Logged out successfully');
}));

router.get('/me', protect() as any, asyncHandler(async (req: any, res: any) => {
  return ResponseUtil.success(res, req.user, 'User retrieved');
}));

export default router;
