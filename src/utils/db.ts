import mongoose from 'mongoose';
import { logger } from './logger';

export const connectDB = async (uri: string): Promise<void> => {
  try {
    if (!uri) {
      throw new Error('MongoDB URI is required');
    }

    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 5000,
    });

    logger.info('✅ MongoDB Connected Successfully');

    mongoose.connection.on('error', (err) => {
      logger.error('MongoDB connection error:', err);
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn('MongoDB disconnected');
    });

  } catch (err) {
    logger.error('❌ MongoDB Connection Failed:', err);
    throw err;
  }
};

export const disconnectDB = async (): Promise<void> => {
  try {
    await mongoose.connection.close();
    logger.info('MongoDB disconnected successfully');
  } catch (err) {
    logger.error('Error disconnecting from MongoDB:', err);
    throw err;
  }
};
