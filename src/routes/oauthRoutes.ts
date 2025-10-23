import express from 'express';
import passport from 'passport';
import { generateTokenPair } from '../core/jwt';
import { User } from '../core/userModel';
import { ResponseUtil } from '../utils/response';

const router = express.Router();

// Google OAuth
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'], session: false }));

router.get(
  '/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: '/login' }),
  async (req: any, res) => {
    try {
      const user = req.user;
      const tokens = generateTokenPair({ id: user._id.toString(), email: user.email, role: user.role });

      // Save refresh token
      await User.findByIdAndUpdate(user._id, { refreshToken: tokens.refreshToken });

      return ResponseUtil.success(res, {
        user: user.toJSON(),
        ...tokens,
      }, 'Google authentication successful');
    } catch (error) {
      return ResponseUtil.serverError(res, 'OAuth callback failed');
    }
  }
);

// GitHub OAuth
router.get('/github', passport.authenticate('github', { scope: ['user:email'], session: false }));

router.get(
  '/github/callback',
  passport.authenticate('github', { session: false, failureRedirect: '/login' }),
  async (req: any, res) => {
    try {
      const user = req.user;
      const tokens = generateTokenPair({ id: user._id.toString(), email: user.email, role: user.role });

      // Save refresh token
      await User.findByIdAndUpdate(user._id, { refreshToken: tokens.refreshToken });

      return ResponseUtil.success(res, {
        user: user.toJSON(),
        ...tokens,
      }, 'GitHub authentication successful');
    } catch (error) {
      return ResponseUtil.serverError(res, 'OAuth callback failed');
    }
  }
);

export default router;
