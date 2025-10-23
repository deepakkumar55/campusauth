import { CampusAuthConfig } from '../types';

class Config {
  private static instance: Config;
  private config: CampusAuthConfig;

  private constructor() {
    this.config = {
      jwtSecret: process.env.JWT_SECRET || 'default-secret-change-in-production',
      jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || 'default-refresh-secret',
      jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1h',
      jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
      mongoUri: process.env.MONGO_URI,
      oauth: {
        google: process.env.GOOGLE_CLIENT_ID ? {
          clientId: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
          callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback',
        } : undefined,
        github: process.env.GITHUB_CLIENT_ID ? {
          clientId: process.env.GITHUB_CLIENT_ID,
          clientSecret: process.env.GITHUB_CLIENT_SECRET!,
          callbackURL: process.env.GITHUB_CALLBACK_URL || '/auth/github/callback',
        } : undefined,
      },
    };
  }

  static getInstance(): Config {
    if (!Config.instance) {
      Config.instance = new Config();
    }
    return Config.instance;
  }

  get(key?: keyof CampusAuthConfig): any {
    if (!key) return this.config;
    return this.config[key];
  }

  set(config: Partial<CampusAuthConfig>): void {
    this.config = { ...this.config, ...config };
  }
}

export const config = Config.getInstance();
