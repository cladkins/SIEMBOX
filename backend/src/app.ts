import 'express-async-errors'; // Must be imported before routes
import express, { Application, Request, Response } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { errorHandler, notFoundHandler } from './middleware/errorHandler';
import { authenticate } from './middleware/auth';
import { query } from './config/database';

// Import routes
import authRoutes from './routes/auth';
import usersRoutes from './routes/users';
import logsRoutes from './routes/logs';
import parsersRoutes from './routes/parsers';
import rulesRoutes from './routes/rules';
import alertsRoutes from './routes/alerts';
import settingsRoutes from './routes/settings';
import shippersRoutes from './routes/shippers';
import assetsRoutes from './routes/assets';
import vulnerabilitiesRoutes from './routes/vulnerabilities';
import adminRoutes from './routes/admin';
import scheduledScansRoutes from './routes/scheduledScans';
import notificationsRoutes from './routes/notifications';
import aiRoutes from './routes/ai';
import containersRoutes from './routes/containers';

const app: Application = express();

// Trust proxy - needed when behind nginx/reverse proxy
app.set('trust proxy', 1);

// Middleware
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true,
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Rate limiting - generous global limit for normal API usage
// Specific rate limiters are applied to scan endpoints in their routes
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // Limit each IP to 1000 requests per windowMs (generous for UI polling)
  message: 'Too many requests from this IP, please try again later.',
  skip: (req: Request) => {
    // Skip rate limiting for authenticated admin users
    return (req as any).user?.role === 'admin';
  },
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

// Database status endpoint
app.get('/health/database-status', async (_req: Request, res: Response) => {
  try {
    const parsers = await query('SELECT COUNT(*) as count FROM parsers');
    const rules = await query('SELECT COUNT(*) as count FROM detection_rules');
    const parserCount = parseInt(parsers.rows[0].count, 10);
    const ruleCount = parseInt(rules.rows[0].count, 10);

    res.status(200).json({
      parsers: parserCount,
      rules: ruleCount,
      ready: parserCount >= 18 && ruleCount >= 40
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to check database status',
      parsers: 0,
      rules: 0,
      ready: false
    });
  }
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
app.use('/api/assets', assetsRoutes); // Asset discovery and management
app.use('/api/vulnerabilities', vulnerabilitiesRoutes); // Vulnerability scanning and management
app.use('/api/admin', adminRoutes); // Admin dashboard (requires admin role)
app.use('/api/scheduled-scans', authenticate, scheduledScansRoutes); // Recurring scheduled scans
app.use('/api/notifications', authenticate, notificationsRoutes);
app.use('/api/ai', authenticate, aiRoutes); // "Explain this" assistant (any authed user)
app.use('/api/containers', authenticate, containersRoutes); // Trivy container image scanning // Notification channels & preferences

// Error handlers (must be last)
app.use(notFoundHandler);
app.use(errorHandler);

export default app;
