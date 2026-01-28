import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { ErrorLogService } from '../services/errors/errorLogService';

export class ApiError extends Error {
  statusCode: number;
  isOperational: boolean;

  constructor(statusCode: number, message: string, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    Error.captureStackTrace(this, this.constructor);
  }
}

export const errorHandler = (
  err: Error | ApiError,
  req: Request,
  res: Response,
  _next: NextFunction
) => {
  // Build error context for logging
  const errorContext = {
    endpoint: req.path,
    method: req.method,
    userId: req.user?.id,
    userAgent: req.get('User-Agent'),
    ip: req.ip,
  };

  if (err instanceof ApiError) {
    logger.error('API Error:', {
      statusCode: err.statusCode,
      message: err.message,
      path: req.path,
      method: req.method,
    });

    // Log operational errors (4xx) only if they're server-related or security issues
    // Skip logging common client errors like 404, 400, 401
    if (err.statusCode >= 500 || err.statusCode === 403) {
      ErrorLogService.logError(err, errorContext).catch(() => {
        // Silently ignore logging failures
      });
    }

    return res.status(err.statusCode).json({
      status: 'error',
      statusCode: err.statusCode,
      message: err.message,
    });
  }

  // Log all unexpected errors to the database
  ErrorLogService.logError(err, errorContext).catch(() => {
    // Silently ignore logging failures
  });

  logger.error('Unexpected error:', {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
  });

  return res.status(500).json({
    status: 'error',
    statusCode: 500,
    message: process.env.NODE_ENV === 'production'
      ? 'Internal server error'
      : err.message,
  });
};

export const notFoundHandler = (req: Request, res: Response) => {
  res.status(404).json({
    status: 'error',
    statusCode: 404,
    message: `Route ${req.originalUrl} not found`,
  });
};
