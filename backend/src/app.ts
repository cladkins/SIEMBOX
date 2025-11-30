import express, { Application } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { errorHandler, notFoundHandler } from './middleware/errorHandler';
import { authenticate } from './middleware/auth';

// Import routes
import authRoutes from './routes/auth';
import usersRoutes from './routes/users';
import logsRoutes from './routes/logs';
import parsersRoutes from './routes/parsers';
import rulesRoutes from './routes/rules';
import alertsRoutes from './routes/alerts';
import settingsRoutes from './routes/settings';
import shippersRoutes from './routes/shippers';

const app: Application = express();

// Middleware
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true,
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
});

app.use('/api/', limiter);

// Health check endpoint
app.get('/health', (_req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', usersRoutes);

// Protected routes (require authentication)
app.use('/api/logs', authenticate, logsRoutes);
app.use('/api/parsers', authenticate, parsersRoutes);
app.use('/api/rules', authenticate, rulesRoutes);
app.use('/api/alerts', authenticate, alertsRoutes);
app.use('/api/settings', authenticate, settingsRoutes);
app.use('/api/shippers', shippersRoutes); // Some endpoints public for shipper registration

// Error handlers (must be last)
app.use(notFoundHandler);
app.use(errorHandler);

export default app;
