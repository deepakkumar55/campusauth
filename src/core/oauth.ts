import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as GitHubStrategy } from 'passport-github2';
import { User } from './userModel';
import { config } from '../config/config';
import { logger } from '../utils/logger';

export const setupOAuth = (): void => {
  const oauthConfig = config.get('oauth');

  if (oauthConfig?.google) {
    logger.info('Setting up Google OAuth');
    passport.use(
      new GoogleStrategy(
        {
          clientID: oauthConfig.google.clientId,
          clientSecret: oauthConfig.google.clientSecret,
          callbackURL: oauthConfig.google.callbackURL,
        },
        async (
          _accessToken: string,
          _refreshToken: string,
          profile: any,
          done: (error: any, user?: any) => void
        ) => {
          try {
            const email = profile.emails?.[0]?.value;
            if (!email) return done(new Error('No email found'), undefined);

            let user = await User.findOne({ email });
            if (!user) {
              user = await User.create({
                name: profile.displayName,
                email,
                provider: 'google',
                role: 'user',
              });
              logger.info(`New user created via Google: ${email}`);
            }
            done(null, user);
          } catch (error) {
            logger.error('Google OAuth error:', error);
            done(error as Error, undefined);
          }
        }
      )
    );
  }

  if (oauthConfig?.github) {
    logger.info('Setting up GitHub OAuth');
    passport.use(
      new GitHubStrategy(
        {
          clientID: oauthConfig.github.clientId,
          clientSecret: oauthConfig.github.clientSecret,
          callbackURL: oauthConfig.github.callbackURL,
        },
        async (_: string, __: string, profile: any, done: (error: any, user?: any) => void) => {
          try {
            const email = profile.emails?.[0]?.value;
            if (!email) return done(new Error('No email found'), undefined);

            let user = await User.findOne({ email });
            if (!user) {
              user = await User.create({
                name: profile.displayName || profile.username,
                email,
                provider: 'github',
                role: 'user',
              });
              logger.info(`New user created via GitHub: ${email}`);
            }
            done(null, user);
          } catch (error) {
            logger.error('GitHub OAuth error:', error);
            done(error as Error, undefined);
          }
        }
      )
    );
  }

  passport.serializeUser((user: any, done) => done(null, user._id));
  passport.deserializeUser(async (id: string, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (error) {
      done(error, null);
    }
  });
};
