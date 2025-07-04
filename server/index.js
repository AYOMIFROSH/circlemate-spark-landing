const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const mongoSanitize = require('express-mongo-sanitize');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const morgan = require('morgan');
const { v4: uuidv4 } = require('uuid');

const authRouter = require('./routes/authRoutes');
const { verifiedPage } = require('./controllers/authController');
const { securityHeaders, requestLogger } = require('./routes/middleware');
const logger = require('./utils/logger');
const onboardingRouter = require('./routes/onboardingRoutes');
const waitlistRouter = require('./routes/waitListRoutes');
const importCsvRouter = require("./models/importCsv");
const {
    networkCheck,
    mongooseNetworkErrorHandler,
    emailNetworkErrorHandler
} = require('./utils/networkMiddleware');

const app = express();
require('dotenv').config();

// Validate environment variables
const requiredEnvVars = ['DB_ALT_HOST', 'SESSION_SECRET', 'SECRET_KEY', 'AUTH_EMAIL', 'AUTH_PASSWORD'];
const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0) {
    logger.error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
    process.exit(1);
}

const dbAltHost = process.env.DB_ALT_HOST;
const SESSION_SECRET = process.env.SESSION_SECRET;

// Request ID middleware (should be first)
app.use((req, res, next) => {
    req.id = req.headers['x-request-id'] || uuidv4();
    res.setHeader('x-request-id', req.id);
    next();
});

// Compression middleware
app.use(compression());

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'", "https:", "data:"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'self'"],
        },
    },
    crossOriginEmbedderPolicy: false
}));

// Custom security headers
app.use(securityHeaders);

// Request logging
app.use(morgan('combined', {
    stream: logger.stream,
    skip: (req) => {
        // Skip logging for all health check endpoints
        const healthPaths = ['/health', '/api/health', '/health/strict'];
        return healthPaths.includes(req.url) || req.url.startsWith('/health');
    }
}));

app.use(requestLogger);

// Network connectivity check middleware
app.use(networkCheck);

// Rate limiting with Redis store for distributed systems (if available)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: {
        status: 'FAILED',
        message: 'Too many requests from this IP, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logger.warn(`Rate limit exceeded for IP: ${req.ip}, Request ID: ${req.id}`);
        res.status(429).json({
            status: 'FAILED',
            message: 'Too many requests from this IP, please try again later.',
            requestId: req.id
        });
    }
});

app.use(limiter);

// Stricter rate limiting for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // Limit each IP to 20 requests per windowMs for auth endpoints
    message: {
        status: 'FAILED',
        message: 'Too many authentication attempts, please try again later.'
    },
    skipSuccessfulRequests: true, // Don't count successful requests
});

// CORS configuration
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            'http://localhost:8080',
            'https://circlemate-spark-landing2.vercel.app', // <-- frontend
            'https://www.mycirclemate.com',
            'http://localhost:3000',
            process.env.FRONTEND_URL
        ].filter(Boolean);

        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);

        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            logger.warn(`CORS blocked request from origin: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With', 'X-Request-ID'],
    credentials: true,
    maxAge: 86400, // 24 hours
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Trust proxy (important for rate limiting and IP detection)
app.set('trust proxy', 1);

// Body parsing middleware with size limits
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.json({ limit: '10mb' }));

// Cookie parsing middleware
app.use(cookieParser());

// MongoDB sanitization
app.use(
    mongoSanitize({
        onSanitize: ({ req, key }) => {
            logger.warn(`Potentially malicious key detected: ${key} from IP: ${req.ip}, Request ID: ${req.id}`);
        },
    })
);

// Health check route
app.get('/', (req, res) => {
    res.status(200).json({
        status: 'success',
        message: 'API is running',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        version: process.env.API_VERSION || '1.0.0',
        requestId: req.id
    });
});

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Replace your existing health check with this improved version
app.get('/health', async (req, res) => {
    const healthcheck = {
        uptime: process.uptime(),
        message: 'OK',
        timestamp: Date.now(),
        environment: process.env.NODE_ENV || 'development',
        requestId: req.id,
        checks: {
            database: 'checking',
            memory: process.memoryUsage(),
            network: 'connected',
            connectionState: mongoose.connection.readyState
        }
    };

    try {
        // Check connection state first (fast check)
        const connectionState = mongoose.connection.readyState;
        
        if (connectionState === 1) {
            // Connected - do a quick ping with timeout
            const pingPromise = mongoose.connection.db.admin().ping();
            const timeoutPromise = new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Database ping timeout')), 8000)
            );
            
            await Promise.race([pingPromise, timeoutPromise]);
            healthcheck.checks.database = 'connected';
            healthcheck.message = 'OK';
            
        } else if (connectionState === 2) {
            // Currently connecting
            healthcheck.checks.database = 'connecting';
            healthcheck.message = 'Database connecting (cold start)';
            
        } else if (connectionState === 0) {
            // Disconnected - this might be a cold start
            healthcheck.checks.database = 'disconnected';
            healthcheck.message = 'Database disconnected (cold start expected)';
            
        } else {
            // Other states (3 = disconnecting)
            healthcheck.checks.database = 'unknown';
            healthcheck.message = 'Database in transition';
        }
        
        // Always return 200 for basic health check - let monitoring decide what's unhealthy
        res.status(200).json(healthcheck);
        
    } catch (error) {
        // Even on database errors, return 200 but indicate the issue
        healthcheck.checks.database = 'error';
        healthcheck.message = `Database error: ${error.message}`;
        
        // Log the error for debugging
        logger.warn('Health check database error:', {
            error: error.message,
            connectionState: mongoose.connection.readyState,
            requestId: req.id
        });
        
        res.status(200).json(healthcheck);
    }
});

// Optional: Add a stricter health check for critical monitoring
app.get('/health/strict', async (req, res) => {
    const healthcheck = {
        uptime: process.uptime(),
        message: 'OK',
        timestamp: Date.now(),
        environment: process.env.NODE_ENV || 'development',
        requestId: req.id,
        checks: {
            database: 'checking',
            memory: process.memoryUsage(),
            network: 'connected'
        }
    };

    try {
        // Strict check - must be connected and responsive
        if (mongoose.connection.readyState !== 1) {
            throw new Error('Database not connected');
        }
        
        // Ping with shorter timeout for strict check
        const pingPromise = mongoose.connection.db.admin().ping();
        const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Database ping timeout')), 3000)
        );
        
        await Promise.race([pingPromise, timeoutPromise]);
        
        healthcheck.checks.database = 'connected';
        res.status(200).json(healthcheck);
        
    } catch (error) {
        healthcheck.checks.database = 'failed';
        healthcheck.message = 'Service degraded';
        res.status(503).json(healthcheck);
    }
});

// Email verification success page
app.get('/api/verified', verifiedPage);

// Apply auth rate limiting to auth routes
app.use('/api/auth', authLimiter);

app.use("/api", importCsvRouter);

// API versioning
const API_VERSION = 'v1';

// Main routes with versioning
app.use(`/api/${API_VERSION}/auth`, authRouter);
app.use(`/api/${API_VERSION}/waitlist`, waitlistRouter);
app.use(`/api/${API_VERSION}/onboarding`, onboardingRouter);

// Legacy routes (for backward compatibility)
app.use('/api/auth', authRouter);
app.use('/api/waitlist', waitlistRouter);
app.use('/api/onboarding', onboardingRouter);

// API documentation route
app.get('/api/docs', (req, res) => {
    res.json({
        status: 'success',
        message: 'API documentation',
        version: API_VERSION,
        baseUrl: `${req.protocol}://${req.get('host')}/api/${API_VERSION}`,
        endpoints: {
            auth: {
                signup: `POST /api/${API_VERSION}/auth/signup`,
                login: `POST /api/${API_VERSION}/auth/login`,
                logout: `POST /api/${API_VERSION}/auth/logout`,
                verify: `GET /api/${API_VERSION}/auth/verify/:userId/:uniqueString`,
                forgotPassword: `POST /api/${API_VERSION}/auth/forgotpassword`,
                resetPassword: `POST /api/${API_VERSION}/auth/reset-password/:token`,
                me: `GET /api/${API_VERSION}/auth/me`,
                sessions: `GET /api/${API_VERSION}/auth/sessions`,
                refreshToken: `POST /api/${API_VERSION}/auth/refresh`
            },
            waitlist: {
                submit: `POST /api/${API_VERSION}/waitlist/submit`,
                getAll: `GET /api/${API_VERSION}/waitlist`,
                export: `GET /api/${API_VERSION}/waitlist/export`,
                stats: `GET /api/${API_VERSION}/waitlist/stats`
            },
            onboarding: {
                status: `GET /api/${API_VERSION}/onboarding/status`,
                communities: `GET /api/${API_VERSION}/onboarding/communities`,
                community: `POST /api/${API_VERSION}/onboarding/community`,
                profile: `POST /api/${API_VERSION}/onboarding/profile`,
                location: `POST /api/${API_VERSION}/onboarding/location`,
                personality: `POST /api/${API_VERSION}/onboarding/personality`,
                preferences: `POST /api/${API_VERSION}/onboarding/preferences`,
                availability: `POST /api/${API_VERSION}/onboarding/availability`,
                photos: `POST /api/${API_VERSION}/onboarding/photos`,
                deletePhoto: `DELETE /api/${API_VERSION}/onboarding/photos/:photoId`,
                complete: `POST /api/${API_VERSION}/onboarding/complete`,
                skip: `POST /api/${API_VERSION}/onboarding/skip`,
                progress: `GET /api/${API_VERSION}/onboarding/progress`,
                bulkUpdate: `POST /api/${API_VERSION}/onboarding/bulk-update`,
                patchProfileField: `PATCH /api/${API_VERSION}/onboarding/profile/:field`
            }
        }
    });
});

// Static files
app.use('/assets', express.static(path.join(__dirname, '..', 'assets')));

// Support both favicon.ico and favicon.png requests
app.get('/favicon.ico', (req, res) => {
    res.redirect('/favicon.png');
});

app.get('/favicon.png', (req, res) => {
    res.sendFile(path.join(__dirname, 'assets', 'icon.png'), {
        headers: {
            'Content-Type': 'image/png',
            'Cache-Control': 'public, max-age=604800'
        }
    });
});

// 404 handler
app.use('*', (req, res) => {
    logger.warn(`404 - Route not found: ${req.originalUrl}, Request ID: ${req.id}`);
    res.status(404).json({
        status: 'FAILED',
        message: `Route ${req.originalUrl} not found`,
        requestId: req.id
    });
});

// Global error handler
app.use((err, req, res, next) => {
    // Check if headers have already been sent
    if (res.headersSent) {
        return next(err);
    }

    // Set CORS headers for error responses
    const allowedOrigins = [
        'https://circlemate-spark-landing-mbh1.vercel.app',
        'http://localhost:8080',
        'http://localhost:3000',
        'https://www.mycirclemate.com'
    ];
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    // Log error details
    logger.error('Error occurred:', {
        message: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        requestId: req.id,
        timestamp: new Date().toISOString()
    });

    // Don't leak error details in production
    const isDevelopment = process.env.NODE_ENV === 'development';

    // Set default error properties
    err.statusCode = err.statusCode || 500;
    err.status = err.status || 'error';

    // MongoDB duplicate key error
    if (err.code === 11000) {
        const field = Object.keys(err.keyPattern)[0];
        err.statusCode = 409;
        err.message = `${field} already exists`;
    }

    // MongoDB validation error
    if (err.name === 'ValidationError') {
        err.statusCode = 400;
        const errors = Object.values(err.errors).map(e => e.message);
        err.message = `Validation error: ${errors.join(', ')}`;
    }

    // JWT errors
    if (err.name === 'JsonWebTokenError') {
        err.statusCode = 401;
        err.message = 'Invalid token';
    }

    if (err.name === 'TokenExpiredError') {
        err.statusCode = 401;
        err.message = 'Token has expired';
    }

    // Network errors
    if (err.isNetworkError || err.code === 'NETWORK_UNAVAILABLE') {
        err.statusCode = 503;
        err.message = 'Network connection error. Please check your internet connection and try again.';
    }

    // Send error response
    res.status(err.statusCode).json({
        status: err.status,
        message: err.message,
        requestId: req.id,
        ...(isDevelopment && {
            stack: err.stack,
            error: err
        })
    });
});

// Graceful shutdown handlers
let server;

const gracefulShutdown = async (signal) => {
    logger.info(`${signal} received. Starting graceful shutdown...`);

    if (server) {
        server.close(() => {
            logger.info('HTTP server closed');
        });
    }

    try {
        await mongoose.connection.close();
        logger.info('MongoDB connection closed');
        process.exit(0);
    } catch (error) {
        logger.error('Error during shutdown:', error);
        process.exit(1);
    }
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Unhandled rejection handler
process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Don't exit the process in production
    if (process.env.NODE_ENV !== 'production') {
        gracefulShutdown('UNHANDLED_REJECTION');
    }
});

// Uncaught exception handler
process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    gracefulShutdown('UNCAUGHT_EXCEPTION');
});

// Database connection with retry logic
const connectWithRetry = async () => {
    const maxRetries = 5;
    let retries = 0;

    // In your existing connectWithRetry function, just update the mongoOptions:
    const mongoOptions = {
        autoIndex: true,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
        maxPoolSize: 10,
        minPoolSize: 1,
        maxIdleTimeMS: 30000,
        family: 4
    };

    while (retries < maxRetries) {
        try {
            await mongoose.connect(dbAltHost, mongoOptions);
            logger.info('MongoDB connected successfully');

            // Setup network error handler for mongoose
            mongooseNetworkErrorHandler(mongoose);

            break;
        } catch (err) {
            retries++;
            logger.error(`MongoDB connection attempt ${retries} failed:`, err);

            if (retries === maxRetries) {
                throw err;
            }

            logger.info(`Retrying in 5 seconds... (${maxRetries - retries} attempts remaining)`);
            await new Promise(resolve => setTimeout(resolve, 5000));
        }
    }
};

// Database connection and server startup
const startServer = async () => {
    try {
        logger.info('Starting application...');

        // Connect to database with retry
        await connectWithRetry();

        // MongoDB connection event handlers
        mongoose.connection.on('error', (error) => {
            logger.error('MongoDB connection error:', error);
        });

        mongoose.connection.on('disconnected', () => {
            logger.warn('MongoDB disconnected');
        });

        mongoose.connection.on('reconnected', () => {
            logger.info('MongoDB reconnected');
        });

        // Start cleanup job for expired sessions
        const Session = require('./models/sessionModel');
        const User = require('./models/userModel');

        // Session cleanup job
        setInterval(async () => {
            try {
                const result = await Session.cleanupExpired();
                logger.info('Expired sessions cleaned up');
            } catch (error) {
                logger.error('Session cleanup error:', error);
            }
        }, 60 * 60 * 1000); // Run every hour

        // Unverified accounts cleanup job
        setInterval(async () => {
            try {
                const result = await User.cleanupUnverifiedAccounts();
                if (result.deletedCount > 0) {
                    logger.info(`Cleaned up ${result.deletedCount} unverified accounts`);
                }
            } catch (error) {
                logger.error('Unverified accounts cleanup error:', error);
            }
        }, 24 * 60 * 60 * 1000); // Run once per day

        const PORT = process.env.PORT || 3000;
        server = app.listen(PORT, () => {
            logger.info(`Server running on port ${PORT}`);
            logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
            logger.info(`Database: Connected to ${mongoose.connection.name}`);
            logger.info(`Process ID: ${process.pid}`);
            logger.info(`API Version: ${API_VERSION}`);
        });

        // Server error handler
        server.on('error', (error) => {
            logger.error('Server error:', error);
            if (error.code === 'EADDRINUSE') {
                logger.error(`Port ${PORT} is already in use`);
                process.exit(1);
            }
        });

    } catch (error) {
        logger.error('Failed to start server:', error);
        process.exit(1);
    }
};

// Start the application
startServer();

module.exports = app;