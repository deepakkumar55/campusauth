import { ValidationResult } from '../types';

export class ValidationUtil {
  static isEmail(email: string): boolean {
    if (!email || typeof email !== 'string') return false;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email.trim());
  }

  static isStrongPassword(password: string): ValidationResult {
    if (!password || typeof password !== 'string') {
      return { valid: false, message: 'Password is required' };
    }

    if (password.length < 8) {
      return { valid: false, message: 'Password must be at least 8 characters long' };
    }
    if (!/[A-Z]/.test(password)) {
      return { valid: false, message: 'Password must contain at least one uppercase letter' };
    }
    if (!/[a-z]/.test(password)) {
      return { valid: false, message: 'Password must contain at least one lowercase letter' };
    }
    if (!/[0-9]/.test(password)) {
      return { valid: false, message: 'Password must contain at least one number' };
    }
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      return { valid: false, message: 'Password must contain at least one special character' };
    }
    return { valid: true };
  }

  static sanitizeInput(input: string): string {
    if (!input || typeof input !== 'string') return '';
    return input.trim().replace(/[<>"/\\&]/g, '').substring(0, 255);
  }

  static validateRequiredFields(obj: any, fields: string[]): ValidationResult {
    if (!obj || typeof obj !== 'object') {
      return { valid: false, message: 'Invalid input object' };
    }

    const missing = fields.filter(field => 
      !obj[field] || 
      (typeof obj[field] === 'string' && !obj[field].trim())
    );

    if (missing.length > 0) {
      return { valid: false, missing };
    }
    return { valid: true };
  }

  static isValidRole(role: string): boolean {
    const validRoles = ['user', 'admin', 'moderator'];
    return validRoles.includes(role);
  }

  static isValidProvider(provider: string): boolean {
    const validProviders = ['local', 'google', 'github', 'linkedin'];
    return validProviders.includes(provider);
  }

  static sanitizeName(name: string): string {
    if (!name || typeof name !== 'string') return '';
    return name.trim().replace(/[<>"/\\&]/g, '').substring(0, 100);
  }

  static validateObjectId(id: string): boolean {
    const objectIdRegex = /^[0-9a-fA-F]{24}$/;
    return objectIdRegex.test(id);
  }
}
