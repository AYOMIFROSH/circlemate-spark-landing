const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const Session = require('../models/sessionModel');
const logger = require('../utils/logger');
const redis = require('../utils/redis');
const mongoose = require('mongoose');
require('dotenv').config();

// Enhanced authentication middleware with caching and token blacklist checking
exports.authenticate = async (req, res, next) => {
    try {
        let user = null;
        let authMethod = null;

        // Check for session token in cookies first (preferred method)
        const sessionToken = req.cookies.sessionToken;
        if (sessionToken) {
            // Check session cache first
            const cacheKey = `session:${sessionToken}`;
            const cachedSession = await redis.get(cacheKey);
            
            if (cachedSession) {
                const session = JSON.parse(cachedSession);
                user = session.userId;
                authMethod = 'session';
                
                // Update last accessed time (throttled)
                const lastUpdateKey = `session:lastupdate:${sessionToken}`;
                const lastUpdate = await redis.get(lastUpdateKey);
                if (!lastUpdate) {
                    Session.updateOne(
                        { sessionToken },
                        { lastAccessed: new Date() }
                    ).catch(err => logger.error('Failed to update session last accessed:', err));
                    await redis.setex(lastUpdateKey, 60, 'true');
                }
            } else {
                // Fallback to database
                const session = await Session.findOne({
                    sessionToken,
                    isActive: true,
                    expiresAt: { $gt: new Date() }
                }).populate('userId').lean();

                if (session && session.userId) {
                    user = session.userId;
                    authMethod = 'session';
                    
                    // Cache the session
                    await redis.setex(cacheKey, 300, JSON.stringify(session));
                    
                    // Update last accessed time
                    session.lastAccessed = new Date();
                    await session.save();
                }
            }
        }

        // If no valid session, check for JWT token
        if (!user) {
            const authHeader = req.headers.authorization;
            const jwtToken = authHeader?.split(' ')[1] || req.cookies.authToken;
            
            if (jwtToken) {
                try {
                    // Verify JWT with options
                    const decoded = jwt.verify(jwtToken, process.env.SECRET_KEY, {
                        algorithms: ['HS256'],
                        issuer: 'circlemate',
                        audience: 'circlemate-users'
                    });
                    
                    // Check if token is blacklisted
                    if (decoded.tokenId) {
                        const blacklisted = await redis.get(`blacklist:token:${decoded.tokenId}`);
                        if (blacklisted) {
                            throw new Error('Token has been revoked');
                        }
                    }
                    
                    // Check user cache
                    const userCacheKey = `user:${decoded._id}`;
                    const cachedUser = await redis.get(userCacheKey);
                    
                    if (cachedUser) {
                        user = JSON.parse(cachedUser);
                    } else {
                        user = await User.findById(decoded._id)
                            .select('-password -resetToken -resetTokenExpiry -refreshToken')
                            .lean();
                        
                        if (user) {
                            // Cache user for 5 minutes
                            await redis.setex(userCacheKey, 300, JSON.stringify(user));
                        }
                    }
                    
                    authMethod = 'jwt';
                } catch (jwtError) {
                    logger.warn('JWT verification failed:', jwtError.message);
                }
            }
        }

        if (!user) {
            return res.status(401).json({ 
                status: 'FAILED',
                message: 'Authentication failed! Please log in.' 
            });
        }

        // Check if user is still verified
        if (!user.verified) {
            return res.status(401).json({
                status: 'FAILED',
                message: 'Account not verified. Please verify your email.'
            });
        }

        // Check if account is locked
        if (user.accountLockedUntil && user.accountLockedUntil > new Date()) {
            return res.status(423).json({
                status: 'FAILED',
                message: 'Account is temporarily locked due to multiple failed login attempts.'
            });
        }

        // Check if account is active
        if (user.isActive === false) {
            return res.status(403).json({
                status: 'FAILED',
                message: 'Account has been deactivated.'
            });
        }

        // Attach user and auth method to request
        req.user = user;
        req.authMethod = authMethod;
        
        logger.debug(`Authenticated user: ${user.email} via ${authMethod}`);
        next();
    } catch (error) {
        logger.error('Authentication error:', error);
        return res.status(401).json({ 
            status: 'FAILED',
            message: 'Authentication failed!' 
        });
    }
};

// Admin verification middleware with role caching
exports.verifyAdmin = async (req, res, next) => {
    try {
        // First authenticate the user
        await new Promise((resolve, reject) => {
            exports.authenticate(req, res, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        // Check admin role cache
        const adminCacheKey = `admin:${req.user._id}`;
        const isAdminCached = await redis.get(adminCacheKey);
        
        if (isAdminCached === 'true') {
            return next();
        }

        // Check if user has admin role
        if (req.user.role !== 'admin' && req.user.role !== 'Admin') {
            logger.warn(`Non-admin user ${req.user.email} attempted to access admin route`);
            return res.status(403).json({ 
                status: 'FAILED',
                message: 'Forbidden: Admin access required' 
            });
        }

        // Cache admin status for 10 minutes
        await redis.setex(adminCacheKey, 600, 'true');
        next();
    } catch (error) {
        return res.status(401).json({ 
            status: 'FAILED',
            message: 'Authentication failed!' 
        });
    }
};

// Optional authentication middleware
exports.optionalAuth = async (req, res, next) => {
    try {
        const sessionToken = req.cookies.sessionToken;
        const authHeader = req.headers.authorization;
        const jwtToken = authHeader?.split(' ')[1] || req.cookies.authToken;

        if (sessionToken) {
            const session = await Session.findOne({
                sessionToken,
                isActive: true,
                expiresAt: { $gt: new Date() }
            }).populate('userId').lean();

            if (session && session.userId) {
                req.user = session.userId;
                req.authMethod = 'session';
                
                // Update last accessed asynchronously
                Session.updateOne(
                    { sessionToken },
                    { lastAccessed: new Date() }
                ).catch(err => logger.error('Failed to update session:', err));
            }
        } else if (jwtToken) {
            try {
                const decoded = jwt.verify(jwtToken, process.env.SECRET_KEY, {
                    algorithms: ['HS256'],
                    issuer: 'circlemate',
                    audience: 'circlemate-users'
                });
                
                const user = await User.findById(decoded._id)
                    .select('-password -resetToken -resetTokenExpiry -refreshToken')
                    .lean();
                    
                if (user && user.verified) {
                    req.user = user;
                    req.authMethod = 'jwt';
                }
            } catch (jwtError) {
                // Ignore JWT errors for optional auth
            }
        }

        next();
    } catch (error) {
        // Don't fail on errors for optional auth
        next();
    }
};

// Enhanced rate limiting with Redis
exports.createRateLimiter = (options = {}) => {
    const {
        windowMs = 15 * 60 * 1000, // 15 minutes
        max = 100, // max requests per window
        keyPrefix = 'rl',
        skipSuccessfulRequests = false,
        message = 'Too many requests, please try again later.'
    } = options;

    return async (req, res, next) => {
        const key = `${keyPrefix}:${req.ip}`;
        const limit = max;
        const window = Math.floor(windowMs / 1000); // Convert to seconds
        
        try {
            const result = await redis.checkRateLimit(key, limit, window);
            
            // Set rate limit headers
            res.setHeader('X-RateLimit-Limit', limit);
            res.setHeader('X-RateLimit-Remaining', result.remaining);
            res.setHeader('X-RateLimit-Reset', new Date(Date.now() + result.resetIn * 1000).toISOString());
            
            if (!result.allowed) {
                logger.warn(`Rate limit exceeded for IP: ${req.ip} on ${req.path}`);
                return res.status(429).json({
                    status: 'FAILED',
                    message,
                    retryAfter: result.resetIn
                });
            }
            
            // Handle skipSuccessfulRequests
            if (skipSuccessfulRequests) {
                const originalSend = res.send;
                res.send = function(data) {
                    if (res.statusCode < 400) {
                        // Decrement the counter for successful requests
                        redis.incr(key, -1).catch(err => 
                            logger.error('Failed to decrement rate limit counter:', err)
                        );
                    }
                    return originalSend.call(this, data);
                };
            }
            
            next();
        } catch (error) {
            logger.error('Rate limiting error:', error);
            // Fail open - allow request if Redis is down
            next();
        }
    };
};

// Login rate limiting
exports.loginRateLimit = exports.createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,
    keyPrefix: 'rl:login',
    skipSuccessfulRequests: true,
    message: 'Too many login attempts. Please try again later.'
});

// API rate limiting
exports.apiRateLimit = exports.createRateLimiter({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    keyPrefix: 'rl:api'
});

// Strict rate limiting for sensitive operations
exports.strictRateLimit = exports.createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3,
    keyPrefix: 'rl:strict',
    message: 'Too many attempts. Please try again in an hour.'
});

// CSRF protection middleware
exports.csrfProtection = (req, res, next) => {
    // Skip CSRF for GET requests and certain API endpoints
    if (req.method === 'GET' || 
        req.path.includes('/api/auth/verify') ||
        req.path.includes('/api/auth/reset-password')) {
        return next();
    }

    const csrfToken = req.headers['x-csrf-token'] || req.body.csrfToken;
    const sessionCsrf = req.session?.csrfToken;

    if (!csrfToken || !sessionCsrf || csrfToken !== sessionCsrf) {
        logger.warn(`CSRF token mismatch for ${req.method} ${req.path} from IP: ${req.ip}`);
        return res.status(403).json({
            status: 'FAILED',
            message: 'Invalid CSRF token'
        });
    }

    next();
};

// Session refresh middleware
exports.refreshSession = async (req, res, next) => {
    try {
        const sessionToken = req.cookies.sessionToken;
        
        if (sessionToken && req.user && req.authMethod === 'session') {
            const session = await Session.findOne({ sessionToken }).lean();
            
            if (session) {
                const timeUntilExpiry = new Date(session.expiresAt) - new Date();
                const refreshThreshold = 2 * 60 * 60 * 1000; // 2 hours
                
                // If session expires in less than 2 hours, extend it
                if (timeUntilExpiry < refreshThreshold) {
                    await Session.updateOne(
                        { sessionToken },
                        { expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) }
                    );
                    
                    // Clear session cache to force refresh
                    await redis.del(`session:${sessionToken}`);
                    
                    // Update cookie expiration
                    const cookieOptions = {
                        httpOnly: true,
                        secure: process.env.NODE_ENV === 'production',
                        sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
                        maxAge: 24 * 60 * 60 * 1000,
                        path: '/'
                    };
                    
                    res.cookie('sessionToken', sessionToken, cookieOptions);
                    logger.debug(`Session extended for user: ${req.user.email}`);
                }
            }
        }
        
        next();
    } catch (error) {
        logger.error('Session refresh error:', error);
        next(); // Continue even if refresh fails
    }
};

// Enhanced request logging with performance tracking
exports.requestLogger = (req, res, next) => {
    const start = Date.now();
    const startMemory = process.memoryUsage();
    
    // Generate request ID
    req.id = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    res.setHeader('X-Request-ID', req.id);
    
    // Log response after it's sent
    res.on('finish', () => {
        const duration = Date.now() - start;
        const endMemory = process.memoryUsage();
        
        const logData = {
            requestId: req.id,
            method: req.method,
            url: req.originalUrl || req.url,
            status: res.statusCode,
            duration: `${duration}ms`,
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent'),
            user: req.user?.email || 'anonymous',
            memoryDelta: Math.round((endMemory.heapUsed - startMemory.heapUsed) / 1024 / 1024 * 100) / 100 + 'MB'
        };
        
        // Track slow requests
        if (duration > 1000) {
            logger.warn('Slow request detected:', logData);
        } else if (res.statusCode >= 400) {
            logger.error('Request failed:', logData);
        } else {
            logger.info('Request completed:', logData);
        }
        
        // Track metrics in Redis (fire and forget)
        redis.lpush('metrics:requests', JSON.stringify({
            ...logData,
            timestamp: new Date().toISOString()
        })).catch(err => logger.error('Failed to track metrics:', err));
        
        // Trim metrics list to last 10000 entries
        redis.ltrim('metrics:requests', 0, 9999).catch(() => {});
    });
    
    next();
};

// Security headers middleware
exports.securityHeaders = (req, res, next) => {
    // Core security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    
    // Content Security Policy
    const cspDirectives = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data: https:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'"
    ];
    
    res.setHeader('Content-Security-Policy', cspDirectives.join('; '));
    
    // Remove sensitive headers
    res.removeHeader('X-Powered-By');
    res.removeHeader('Server');
    
    // HSTS for production
    if (process.env.NODE_ENV === 'production') {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    }
    
    next();
};

// API versioning middleware
exports.apiVersion = (version) => {
    return (req, res, next) => {
        req.apiVersion = version;
        res.setHeader('X-API-Version', version);
        
        // Check if client accepts this version
        const acceptVersion = req.headers['accept-version'];
        if (acceptVersion && acceptVersion !== version) {
            return res.status(406).json({
                status: 'FAILED',
                message: `API version ${acceptVersion} not supported. Current version is ${version}.`
            });
        }
        
        next();
    };
};

// Enhanced pagination middleware
exports.paginate = (req, res, next) => {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(Math.max(1, parseInt(req.query.limit) || 20), 100); // Max 100 items
    const skip = (page - 1) * limit;
    const sort = req.query.sort || '-createdAt';
    
    req.pagination = {
        page,
        limit,
        skip,
        sort
    };
    
    // Add pagination helper to response
    res.paginate = (total) => {
        return {
            page,
            limit,
            total,
            pages: Math.ceil(total / limit),
            hasNext: page < Math.ceil(total / limit),
            hasPrev: page > 1,
            next: page < Math.ceil(total / limit) ? page + 1 : null,
            prev: page > 1 ? page - 1 : null
        };
    };
    
    next();
};

// Cache middleware
exports.cache = (duration = 300) => {
    return async (req, res, next) => {
        // Only cache GET requests
        if (req.method !== 'GET') {
            return next();
        }
        
        const key = `cache:${req.originalUrl || req.url}`;
        
        try {
            const cached = await redis.get(key);
            if (cached) {
                res.setHeader('X-Cache', 'HIT');
                return res.json(JSON.parse(cached));
            }
            
            // Store original json method
            const originalJson = res.json;
            res.json = function(data) {
                res.setHeader('X-Cache', 'MISS');
                // Cache the response
                redis.setex(key, duration, JSON.stringify(data))
                    .catch(err => logger.error('Cache set error:', err));
                return originalJson.call(this, data);
            };
            
            next();
        } catch (error) {
            logger.error('Cache middleware error:', error);
            next(); // Continue without cache on error
        }
    };
};

// Async error handler wrapper
exports.asyncHandler = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

// Validate MongoDB ObjectId
exports.validateObjectId = (paramName = 'id') => {
    return (req, res, next) => {
        const id = req.params[paramName];
        
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({
                status: 'FAILED',
                message: `Invalid ${paramName} format`
            });
        }
        
        next();
    };
};

// Request sanitization middleware
exports.sanitizeRequest = (req, res, next) => {
    // Sanitize query parameters
    if (req.query) {
        for (const key in req.query) {
            if (typeof req.query[key] === 'string') {
                // Remove any MongoDB operators
                req.query[key] = req.query[key].replace(/[$]/g, '');
            }
        }
    }
    
    // Sanitize body
    if (req.body) {
        const sanitizeObject = (obj) => {
            for (const key in obj) {
                if (typeof obj[key] === 'string') {
                    // Remove MongoDB operators
                    obj[key] = obj[key].replace(/[$]/g, '');
                    // Trim whitespace
                    obj[key] = obj[key].trim();
                } else if (typeof obj[key] === 'object' && obj[key] !== null) {
                    sanitizeObject(obj[key]);
                }
            }
        };
        sanitizeObject(req.body);
    }
    
    next();
};

// IP-based blocking middleware
exports.ipBlocker = async (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const blockedKey = `blocked:ip:${ip}`;
    
    try {
        const isBlocked = await redis.get(blockedKey);
        if (isBlocked) {
            logger.warn(`Blocked IP attempted access: ${ip}`);
            return res.status(403).json({
                status: 'FAILED',
                message: 'Access denied'
            });
        }
        
        // Check for suspicious activity
        const suspiciousKey = `suspicious:ip:${ip}`;
        const suspiciousCount = await redis.incr(suspiciousKey);
        await redis.expire(suspiciousKey, 3600); // 1 hour window
        
        if (suspiciousCount > 100) { // 100 suspicious requests per hour
            await redis.setex(blockedKey, 86400, 'true'); // Block for 24 hours
            logger.warn(`IP blocked due to suspicious activity: ${ip}`);
            return res.status(403).json({
                status: 'FAILED',
                message: 'Access denied due to suspicious activity'
            });
        }
        
        next();
    } catch (error) {
        logger.error('IP blocker error:', error);
        next(); // Fail open
    }
};

// Request timeout middleware
exports.timeout = (seconds = 30) => {
    return (req, res, next) => {
        const timeoutId = setTimeout(() => {
            if (!res.headersSent) {
                logger.error(`Request timeout: ${req.method} ${req.originalUrl}`);
                res.status(504).json({
                    status: 'FAILED',
                    message: 'Request timeout'
                });
            }
        }, seconds * 1000);
        
        res.on('finish', () => {
            clearTimeout(timeoutId);
        });
        
        next();
    };
};

// Compression settings based on content type
exports.compressionOptions = {
    filter: (req, res) => {
        // Don't compress responses with this request header
        if (req.headers['x-no-compression']) {
            return false;
        }
        
        // Compress everything else
        return true;
    },
    level: 6, // Balanced compression level
    threshold: 1024, // Only compress responses larger than 1KB
};

// CORS configuration function
exports.corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            'http://localhost:8080',
            'http://localhost:3000',
            'https://circlemate-spark-landing-mbh1.vercel.app',
            'https://www.mycirclemate.com',
            process.env.FRONTEND_URL
        ].filter(Boolean);
        
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1 || process.env.NODE_ENV === 'development') {
            callback(null, true);
        } else {
            logger.warn(`CORS blocked request from origin: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With', 'Accept-Version'],
    exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'X-Request-ID'],
    maxAge: 86400, // 24 hours
    optionsSuccessStatus: 200
};

// Health check middleware
exports.healthCheck = (req, res, next) => {
    if (req.path === '/health' || req.path === '/readiness') {
        return next();
    }
    
    // Check system health
    const memoryUsage = process.memoryUsage();
    const uptime = process.uptime();
    
    if (memoryUsage.heapUsed > 0.95 * memoryUsage.heapTotal) { // Changed from 0.9 to 0.95 (95%)
        logger.error('Memory usage critical:', {
            used: Math.round(memoryUsage.heapUsed / 1024 / 1024) + 'MB',
            total: Math.round(memoryUsage.heapTotal / 1024 / 1024) + 'MB'
        });
    }
    
    next();
};

// Performance monitoring middleware
exports.performanceMonitor = (req, res, next) => {
    const start = process.hrtime.bigint();
    
    res.on('finish', () => {
        const end = process.hrtime.bigint();
        const duration = Number(end - start) / 1_000_000; // Convert to milliseconds
        
        // Log slow endpoints
        if (duration > 2000) { // Changed from 1000ms to 2000ms for development
            logger.warn('Slow endpoint detected:', {
                method: req.method,
                path: req.route?.path || req.path,
                duration: `${duration.toFixed(2)}ms`,
                params: req.params,
                query: req.query
            });
        }
        
        // Track endpoint performance metrics
        const metricKey = `metrics:endpoint:${req.method}:${req.route?.path || req.path}`;
        redis.lpush(metricKey, JSON.stringify({
            duration,
            status: res.statusCode,
            timestamp: new Date().toISOString()
        })).catch(() => {});
        
        // Keep only last 1000 entries per endpoint
        redis.ltrim(metricKey, 0, 999).catch(() => {});
    });
    
    next();
};

// Maintenance mode middleware
exports.maintenanceMode = async (req, res, next) => {
    try {
        const maintenanceMode = await redis.get('maintenance:mode');
        
        if (maintenanceMode === 'true') {
            const maintenanceMessage = await redis.get('maintenance:message') || 
                'System is under maintenance. Please try again later.';
            
            return res.status(503).json({
                status: 'FAILED',
                message: maintenanceMessage,
                retryAfter: 3600 // 1 hour
            });
        }
        
        next();
    } catch (error) {
        logger.error('Maintenance mode check error:', error);
        next(); // Fail open
    }
};

// Request ID generator
exports.generateRequestId = (req, res, next) => {
    req.id = req.headers['x-request-id'] || 
             `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    res.setHeader('X-Request-ID', req.id);
    next();
};

// Error response formatter
exports.formatErrorResponse = (err, req, res, next) => {
    const isDevelopment = process.env.NODE_ENV === 'development';
    
    // Default error properties
    const statusCode = err.statusCode || 500;
    const status = err.status || 'error';
    const message = err.message || 'Internal server error';
    
    // Log error details
    logger.error('Error occurred:', {
        requestId: req.id,
        error: {
            message: err.message,
            stack: err.stack,
            statusCode,
            status
        },
        request: {
            method: req.method,
            url: req.originalUrl,
            ip: req.ip,
            user: req.user?.email
        }
    });
    
    // Send error response
    res.status(statusCode).json({
        status,
        message,
        requestId: req.id,
        ...(isDevelopment && {
            error: err,
            stack: err.stack
        })
    });
};

// Export middleware collection for easy use
exports.defaultMiddleware = [
    exports.generateRequestId,
    exports.securityHeaders,
    exports.requestLogger,
    exports.healthCheck,
    exports.ipBlocker,
    exports.sanitizeRequest,
    exports.performanceMonitor
];

exports.authMiddleware = [
    exports.authenticate,
    exports.refreshSession
];

exports.adminMiddleware = [
    exports.authenticate,
    exports.verifyAdmin
];