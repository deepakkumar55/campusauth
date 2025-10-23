import { CampusAuthConfig } from '../types';
import { logger } from '../utils/logger';

class Config {
  private static instance: Config;
  private config: CampusAuthConfig;

  private constructor() {
    this.validateEnvironment();
    this.config = this.loadConfiguration();
  }

  static getInstance(): Config {
    if (!Config.instance) {
      Config.instance = new Config();
    }
    return Config.instance;
  }

  private validateEnvironment(): void {
    const required = ['JWT_SECRET'];
    const missing = required.filter(key => !process.env[key]);
    
    if (missing.length > 0) {
      logger.warn(`Missing required environment variables: ${missing.join(', ')}`);
    }

    // Validate JWT secret strength
    if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
      logger.warn('JWT_SECRET should be at least 32 characters long for security');
    }
  }

  private loadConfiguration(): CampusAuthConfig {
    return {
      jwtSecret: process.env.JWT_SECRET || this.generateFallbackSecret(),
      jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || this.generateFallbackSecret(),
      jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1h',
      jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
      mongoUri: process.env.MONGO_URI,
      oauth: {
        google: this.getOAuthConfig('GOOGLE'),
        github: this.getOAuthConfig('GITHUB'),
        linkedin: this.getOAuthConfig('LINKEDIN'),
      },
    };
  }

  private getOAuthConfig(provider: string): any {
    const clientId = process.env[`${provider}_CLIENT_ID`];
    const clientSecret = process.env[`${provider}_CLIENT_SECRET`];
    
    if (!clientId || !clientSecret) {
      return undefined;
    }

    const callbackURL = process.env[`${provider}_CALLBACK_URL`] || 
                       `/auth/oauth/${provider.toLowerCase()}/callback`;

    return {
      clientId,
      clientSecret,
      callbackURL,
    };
  }

  private generateFallbackSecret(): string {
    const fallback = 'fallback-secret-change-in-production-' + Date.now();
    logger.warn('Using fallback secret. This should only happen in development!');
    return fallback;
  }

  get<K extends keyof CampusAuthConfig>(key?: K): K extends undefined ? CampusAuthConfig : CampusAuthConfig[K] {
    if (!key) return this.config as any;
    return this.config[key] as any;
  }

  set(newConfig: Partial<CampusAuthConfig>): void {
    this.config = { ...this.config, ...newConfig };
    logger.info('Configuration updated');
  }

  // Get environment-specific settings
  isDevelopment(): boolean {
    return process.env.NODE_ENV === 'development';
  }

  isProduction(): boolean {
    return process.env.NODE_ENV === 'production';
  }

  isTest(): boolean {
    return process.env.NODE_ENV === 'test';
  }

  // Get OAuth providers that are configured
  getConfiguredOAuthProviders(): string[] {
    const providers = [];
    if (this.config.oauth?.google) providers.push('google');
    if (this.config.oauth?.github) providers.push('github');
    if (this.config.oauth?.linkedin) providers.push('linkedin');
    return providers;
  }
}

export const config = Config.getInstance();
