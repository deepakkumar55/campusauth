import mongoose, { Schema } from 'mongoose';
import { IUser } from '../types';

const userSchema = new Schema<IUser>(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String },
    provider: { type: String, enum: ['local', 'google', 'github', 'linkedin'], default: 'local' },
    role: { type: String, default: 'user', enum: ['user', 'admin', 'moderator'] },
    refreshToken: { type: String },
  },
  {
    timestamps: true,
  }
);

// Index for faster queries
userSchema.index({ email: 1 });
userSchema.index({ provider: 1 });

// Remove password from JSON responses
userSchema.set('toJSON', {
  transform: (_, ret) => {
    const r: any = ret;
    delete r.password;
    delete r.refreshToken;
    delete r.__v;
    return r;
  },
});

export const User = mongoose.models.User || mongoose.model<IUser>('User', userSchema);
