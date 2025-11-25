import express, { Application } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { errorHandler, notFoundHandler } from './middleware/errorHandler';
import { logger } from './utils/logger';

// Import routes
import logsRoutes from './routes/logs';
import parsersRoutes from './routes/parsers';
import rulesRoutes from './routes/rules';
import alertsRoutes from './routes/alerts';

const app: Application = express();

// Middleware
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true,
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
});

app.use('/api/', limiter);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// API routes
// app.use('/api/auth', authRoutes); // TODO: Implement authentication
app.use('/api/logs', logsRoutes);
app.use('/api/parsers', parsersRoutes);
app.use('/api/rules', rulesRoutes);
app.use('/api/alerts', alertsRoutes);
// app.use('/api/users', userRoutes); // TODO: Implement user management

// Error handlers (must be last)
app.use(notFoundHandler);
app.use(errorHandler);

export default app;
