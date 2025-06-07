require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const mongoSanitize = require('express-mongo-sanitize');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');

// Import configurations
const { connectDB, disconnectDB } = require('./config/database');
const redis = require('./utils/redis');

// Import routes
const authRouter = require('./routes/authRoutes');
const onboardingRouter = require('./routes/onboardingRoutes');
const waitlistRouter = require('./routes/waitListRoutes');
const importCsvRouter = require("./models/importCsv");

// Import middleware
const {
    defaultMiddleware,
    corsOptions,
    compressionOptions,
    apiRateLimit,
    maintenanceMode,
    formatErrorResponse,
    apiVersion,
    timeout,
    cache
} = require('./routes/middleware');

// Import controllers
const { verifiedPage } = require('./controllers/authController');

// Import utilities
const logger = require('./utils/logger');

const app = express();

// Validate environment variables
const requiredEnvVars = [
    'DB_ALT_HOST', 
    'SESSION_SECRET', 
    'SECRET_KEY', 
    'AUTH_EMAIL', 
    'AUTH_PASSWORD',
    'REDIS_HOST'
];
const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0) {
    logger.error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
    process.exit(1);
}

// Trust proxy (important for rate limiting and IP detection)
app.set('trust proxy', 1);

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ===== MIDDLEWARE SETUP (Order matters!) =====

// 1. Maintenance mode check (first)
app.use(maintenanceMode);

// 2. Default security and logging middleware
app.use(defaultMiddleware);

// 3. Helmet security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'self'"],
        },
    },
    crossOriginEmbedderPolicy: false
}));

// 4. CORS configuration
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// 5. Compression
app.use(compression(compressionOptions));

// 6. Request logging with Morgan
app.use(morgan('combined', { 
    stream: { 
        write: message => logger.info(message.trim()) 
    },
    skip: (req, res) => res.statusCode < 400 // Only log errors in production
}));

// 7. Body parsing with size limits
app.use(express.json({ 
    limit: '10mb',
    verify: (req, res, buf, encoding) => {
        // Save raw body for webhook signature verification if needed
        if (req.headers['x-webhook-signature']) {
            req.rawBody = buf.toString(encoding || 'utf8');
        }
    }
}));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 8. Cookie parsing
app.use(cookieParser());

// 9. MongoDB sanitization
app.use(mongoSanitize({
    replaceWith: '_',
    onSanitize: ({ req, key }) => {
        logger.warn(`Potentially malicious key detected: ${key} from IP: ${req.ip}`);
    },
}));

// 10. Global timeout (30 seconds for all requests)
app.use(timeout(30));

// 11. API rate limiting
app.use('/api/', apiRateLimit);

// ===== ROUTES =====

// Health check endpoints (no auth required)
app.get('/', cache(60), (req, res) => {
    res.status(200).json({
        status: 'success',
        message: 'CircleMate API is running',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        version: process.env.API_VERSION || '1.0.0'
    });
});

// Detailed health check
app.get('/health', async (req, res) => {
    const healthcheck = {
        uptime: process.uptime(),
        message: 'OK',
        timestamp: Date.now(),
        environment: process.env.NODE_ENV || 'development',
        checks: {
            database: 'pending',
            redis: 'pending',
            memory: process.memoryUsage(),
        }
    };

    try {
        // Check database connection
        await mongoose.connection.db.admin().ping();
        healthcheck.checks.database = 'connected';
        
        // Check Redis connection
        await redis.set('health:check', 'ok');
        const redisCheck = await redis.get('health:check');
        healthcheck.checks.redis = redisCheck === 'ok' ? 'connected' : 'error';
        
        // Check memory usage
        const memUsage = process.memoryUsage();
        healthcheck.checks.memoryUsagePercent = Math.round((memUsage.heapUsed / memUsage.heapTotal) * 100);
        
        res.status(200).json(healthcheck);
    } catch (error) {
        healthcheck.checks.database = 'disconnected';
        healthcheck.checks.redis = 'disconnected';
        healthcheck.message = 'Service degraded';
        res.status(503).json(healthcheck);
    }
});

// Readiness check for Kubernetes/load balancers
app.get('/readiness', async (req, res) => {
    try {
        // Check if database is ready
        const dbState = mongoose.connection.readyState;
        if (dbState !== 1) {
            throw new Error('Database not ready');
        }
        
        // Check if Redis is ready
        await redis.get('readiness:check');
        
        res.status(200).json({ status: 'ready' });
    } catch (error) {
        res.status(503).json({ status: 'not ready', error: error.message });
    }
});

// Email verification success page
app.get('/api/verified', verifiedPage);

// API v1 routes with versioning
app.use('/api/v1', apiVersion('1.0.0'));

// Import route with CSV functionality
app.use("/api/v1", importCsvRouter);

// Auth routes with specific rate limiting
app.use('/api/v1/auth', authRouter);

// Waitlist routes (public)
app.use('/api/v1/waitlist', waitlistRouter);

// Onboarding routes (authenticated)
app.use('/api/v1/onboarding', onboardingRouter);

// API documentation
app.get('/api/v1/docs', cache(3600), (req, res) => {
    res.json({
        status: 'success',
        message: 'CircleMate API Documentation',
        version: '1.0.0',
        endpoints: {
            auth: {
                signup: 'POST /api/v1/auth/signup',
                login: 'POST /api/v1/auth/login',
                logout: 'POST /api/v1/auth/logout',
                verify: 'GET /api/v1/auth/verify/:userId/:uniqueString',
                forgotPassword: 'POST /api/v1/auth/forgotpassword',
                resetPassword: 'POST /api/v1/auth/reset-password/:token',
                me: 'GET /api/v1/auth/me',
                sessions: 'GET /api/v1/auth/sessions',
                refreshToken: 'POST /api/v1/auth/refresh'
            },
            waitlist: {
                submit: 'POST /api/v1/waitlist/submit',
                list: 'GET /api/v1/waitlist (admin)',
                export: 'GET /api/v1/waitlist/export (admin)',
                stats: 'GET /api/v1/waitlist/stats (admin)'
            },
            onboarding: {
                status: 'GET /api/v1/onboarding/status',
                community: 'POST /api/v1/onboarding/community',
                profile: 'POST /api/v1/onboarding/profile',
                location: 'POST /api/v1/onboarding/location',
                personality: 'POST /api/v1/onboarding/personality',
                preferences: 'POST /api/v1/onboarding/preferences',
                availability: 'POST /api/v1/onboarding/availability',
                photos: 'POST /api/v1/onboarding/photos',
                complete: 'POST /api/v1/onboarding/complete'
            }
        },
        rateLimit: {
            general: '1000 requests per 15 minutes',
            auth: '20 requests per 15 minutes',
            login: '5 requests per 15 minutes'
        }
    });
});

// Metrics endpoint (internal use only)
app.get('/api/v1/metrics', async (req, res, next) => {
    try {
        // Simple API key authentication for metrics
        const apiKey = req.headers['x-api-key'];
        if (apiKey !== process.env.METRICS_API_KEY) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        
        // Get metrics from Redis
        const requests = await redis.lrange('metrics:requests', 0, 99);
        const stats = await redis.getStats();
        
        res.json({
            timestamp: new Date().toISOString(),
            process: {
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                cpu: process.cpuUsage()
            },
            requests: requests.map(r => JSON.parse(r)),
            redis: stats
        });
    } catch (error) {
        next(error);
    }
});

// Static files with caching
app.use('/assets', express.static(path.join(__dirname, '..', 'assets'), {
    maxAge: '7d',
    etag: true,
    lastModified: true
}));

// Favicon handling
app.get('/favicon.ico', (req, res) => {
    res.redirect(301, '/favicon.png');
});

app.get('/favicon.png', (req, res) => {
    res.sendFile(path.join(__dirname, 'assets', 'icon.png'), {
        headers: {
            'Content-Type': 'image/png',
            'Cache-Control': 'public, max-age=604800' // 7 days
        }
    });
});

// 404 handler
app.use('*', (req, res) => {
    logger.warn(`404 - Route not found: ${req.originalUrl} from IP: ${req.ip}`);
    res.status(404).json({
        status: 'FAILED',
        message: `Route ${req.originalUrl} not found`,
        suggestion: 'Please check the API documentation at /api/v1/docs'
    });
});

// Global error handler
app.use(formatErrorResponse);

// ===== GRACEFUL SHUTDOWN =====
let server;

const gracefulShutdown = async (signal) => {
    logger.info(`${signal} received. Starting graceful shutdown...`);
    
    // Stop accepting new connections
    if (server) {
        server.close(() => {
            logger.info('HTTP server closed');
        });
    }

    try {
        // Close database connections
        await disconnectDB();
        
        // Close Redis connection
        await redis.flushdb(); // Clear any pending operations
        
        logger.info('All connections closed successfully');
        process.exit(0);
    } catch (error) {
        logger.error('Error during shutdown:', error);
        process.exit(1);
    }
};

// Handle shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught errors
process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Don't exit in production, just log
    if (process.env.NODE_ENV !== 'production') {
        gracefulShutdown('UNHANDLED_REJECTION');
    }
});

process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    // Always exit on uncaught exceptions
    gracefulShutdown('UNCAUGHT_EXCEPTION');
});

// ===== SCHEDULED JOBS =====
const setupScheduledJobs = () => {
    const Session = require('./models/sessionModel');
    const User = require('./models/userModel');
    
    // Session cleanup job - runs every hour
    setInterval(async () => {
        try {
            const result = await Session.cleanupExpired();
            logger.info('Expired sessions cleanup completed');
        } catch (error) {
            logger.error('Session cleanup error:', error);
        }
    }, 60 * 60 * 1000);

    // Unverified accounts cleanup - runs once per day
    setInterval(async () => {
        try {
            const result = await User.cleanupUnverifiedAccounts();
            if (result.deletedCount > 0) {
                logger.info(`Cleaned up ${result.deletedCount} unverified accounts`);
            }
        } catch (error) {
            logger.error('Unverified accounts cleanup error:', error);
        }
    }, 24 * 60 * 60 * 1000);

    // Redis metrics cleanup - runs every 6 hours
    setInterval(async () => {
        try {
            // Clean old metrics
            const patterns = ['metrics:endpoint:*', 'metrics:requests'];
            for (const pattern of patterns) {
                const keys = await redis.keys(pattern);
                for (const key of keys) {
                    await redis.ltrim(key, 0, 999); // Keep last 1000 entries
                }
            }
            logger.info('Metrics cleanup completed');
        } catch (error) {
            logger.error('Metrics cleanup error:', error);
        }
    }, 6 * 60 * 60 * 1000);

    logger.info('Scheduled jobs initialized');
};

// ===== SERVER STARTUP =====
const startServer = async () => {
    try {
        logger.info('Starting CircleMate server...');
        
        // Connect to MongoDB
        await connectDB();
        
        // Verify Redis connection
        await redis.set('startup:check', new Date().toISOString());
        logger.info('Redis connection verified');
        
        // Setup scheduled jobs
        if (!process.env.WORKER_NAME || process.env.WORKER_NAME === 'primary') {
            setupScheduledJobs();
        }
        
        // Start server
        const PORT = process.env.PORT || 3000;
        server = app.listen(PORT, '0.0.0.0', () => {
            logger.info(`Server running on port ${PORT}`);
            logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
            logger.info(`Process ID: ${process.pid}`);
            logger.info(`Node version: ${process.version}`);
            
            // Log startup metrics
            const usage = process.memoryUsage();
            logger.info('Startup memory usage:', {
                rss: `${Math.round(usage.rss / 1024 / 1024)}MB`,
                heapTotal: `${Math.round(usage.heapTotal / 1024 / 1024)}MB`,
                heapUsed: `${Math.round(usage.heapUsed / 1024 / 1024)}MB`
            });
        });

        // Handle server errors
        server.on('error', (error) => {
            logger.error('Server error:', error);
            if (error.code === 'EADDRINUSE') {
                logger.error(`Port ${PORT} is already in use`);
                process.exit(1);
            }
        });

        // Set server timeout
        server.timeout = 60000; // 60 seconds
        server.keepAliveTimeout = 65000; // 65 seconds
        server.headersTimeout = 66000; // 66 seconds

    } catch (error) {
        logger.error('Failed to start server:', error);
        process.exit(1);
    }
};

// Start the application
startServer();

// Export for testing
module.exports = app;