import mongoose, { Schema, Document } from 'mongoose';
import { IUser } from '../types';

interface IUserDocument extends Omit<IUser, '_id' | 'toJSON'>, Document {
  comparePassword(password: string): Promise<boolean>;
  generateTokens(): { accessToken: string; refreshToken: string };
}

const userSchema = new Schema<IUserDocument>(
  {
    name: {
      type: String,
      required: [true, 'Name is required'],
      trim: true,
      maxlength: [100, 'Name cannot exceed 100 characters'],
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Please provide a valid email'],
    },
    password: {
      type: String,
      minlength: [8, 'Password must be at least 8 characters long'],
      select: false, // Don't include password in queries by default
    },
    provider: {
      type: String,
      enum: {
        values: ['local', 'google', 'github', 'linkedin'],
        message: 'Invalid provider',
      },
      default: 'local',
    },
    role: {
      type: String,
      enum: {
        values: ['user', 'admin', 'moderator'],
        message: 'Invalid role',
      },
      default: 'user',
    },
    refreshToken: {
      type: String,
      select: false, // Don't include refresh token in queries by default
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Compound indexes for better query performance
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ provider: 1, email: 1 });
userSchema.index({ role: 1 });
userSchema.index({ createdAt: -1 });

// Virtual for user's full profile
userSchema.virtual('profile').get(function () {
  return {
    id: this._id,
    name: this.name,
    email: this.email,
    role: this.role,
    provider: this.provider,
    createdAt: this.createdAt,
    updatedAt: this.updatedAt,
  };
});

// Pre-save middleware for validation
userSchema.pre('save', function (next) {
  // Ensure OAuth users don't have password
  if (this.provider !== 'local' && this.password) {
    this.password = undefined;
  }

  // Ensure local users have password
  if (this.provider === 'local' && this.isNew && !this.password) {
    return next(new Error('Password is required for local users'));
  }

  next();
});

// Remove sensitive data from JSON responses
userSchema.set('toJSON', {
  transform: (_doc, ret) => {
    // use Reflect.deleteProperty to avoid TypeScript 'delete' operand errors
    Reflect.deleteProperty(ret, 'password');
    Reflect.deleteProperty(ret, 'refreshToken');
    Reflect.deleteProperty(ret, '__v');

    // Convert _id to id for consistency
    if (ret._id) {
      ret.id = ret._id.toString();
      Reflect.deleteProperty(ret, '_id');
    }

    return ret;
  },
});

// Static methods
userSchema.statics.findByEmail = function (email: string) {
  return this.findOne({ email: email.toLowerCase() });
};

userSchema.statics.findByProvider = function (provider: string) {
  return this.find({ provider });
};

userSchema.statics.countByRole = function (role: string) {
  return this.countDocuments({ role });
};

// Instance methods
userSchema.methods.updateLastLogin = function () {
  this.lastLoginAt = new Date();
  return this.save();
};

userSchema.methods.clearRefreshToken = function () {
  this.refreshToken = undefined;
  return this.save();
};

// Ensure model is not re-compiled
export const User = mongoose.models.User || mongoose.model<IUserDocument>('User', userSchema);

// Export the interface for TypeScript
export type UserDocument = IUserDocument;
