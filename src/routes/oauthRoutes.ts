import express from 'express';
import passport from 'passport';
import { generateTokenPair } from '../core/jwt';
import { User } from '../core/userModel';
import { ResponseUtil } from '../utils/response';
import { logger } from '../utils/logger';

const router = express.Router();

// Google OAuth initiation
router.get('/google', (req, res, next) => {
  passport.authenticate('google', { 
    scope: ['profile', 'email'],
    session: false 
  })(req, res, next);
});

// Google OAuth callback
router.get('/google/callback', 
  passport.authenticate('google', { 
    session: false, 
    failureRedirect: '/login?error=oauth_failed' 
  }),
  async (req: any, res) => {
    try {
      if (!req.user) {
        logger.warn('Google OAuth callback: No user found');
        return res.redirect('/login?error=oauth_failed');
      }

      const user = req.user;
      const tokens = generateTokenPair({ 
        id: user._id.toString(), 
        email: user.email, 
        role: user.role 
      });

      // Save refresh token
      await User.findByIdAndUpdate(user._id, { refreshToken: tokens.refreshToken });

      logger.info(`Google OAuth successful for user: ${user.email}`);

      // For API usage
      if (req.headers.accept && req.headers.accept.includes('application/json')) {
        return ResponseUtil.success(res, {
          user: user.toJSON(),
          ...tokens,
        }, 'Google authentication successful');
      }

      // For web redirect
      const redirectUrl = req.query.redirect || '/dashboard';
      return res.redirect(`${redirectUrl}?token=${tokens.accessToken}&refresh=${tokens.refreshToken}`);
    } catch (error) {
      logger.error('Google OAuth callback error:', error);
      return res.redirect('/login?error=oauth_callback_failed');
    }
  }
);

// GitHub OAuth initiation
router.get('/github', (req, res, next) => {
  passport.authenticate('github', { 
    scope: ['user:email'],
    session: false 
  })(req, res, next);
});

// GitHub OAuth callback
router.get('/github/callback',
  passport.authenticate('github', { 
    session: false, 
    failureRedirect: '/login?error=oauth_failed' 
  }),
  async (req: any, res) => {
    try {
      if (!req.user) {
        logger.warn('GitHub OAuth callback: No user found');
        return res.redirect('/login?error=oauth_failed');
      }

      const user = req.user;
      const tokens = generateTokenPair({ 
        id: user._id.toString(), 
        email: user.email, 
        role: user.role 
      });

      // Save refresh token
      await User.findByIdAndUpdate(user._id, { refreshToken: tokens.refreshToken });

      logger.info(`GitHub OAuth successful for user: ${user.email}`);

      // For API usage
      if (req.headers.accept && req.headers.accept.includes('application/json')) {
        return ResponseUtil.success(res, {
          user: user.toJSON(),
          ...tokens,
        }, 'GitHub authentication successful');
      }

      // For web redirect
      const redirectUrl = req.query.redirect || '/dashboard';
      return res.redirect(`${redirectUrl}?token=${tokens.accessToken}&refresh=${tokens.refreshToken}`);
    } catch (error) {
      logger.error('GitHub OAuth callback error:', error);
      return res.redirect('/login?error=oauth_callback_failed');
    }
  }
);

// OAuth status check
router.get('/status', (_req, res) => {
  const availableProviders = [];
  
  if (process.env.GOOGLE_CLIENT_ID) {
    availableProviders.push('google');
  }
  
  if (process.env.GITHUB_CLIENT_ID) {
    availableProviders.push('github');
  }

  return ResponseUtil.success(res, {
    providers: availableProviders
  }, 'OAuth providers status');
});

export default router;
