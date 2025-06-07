const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const Session = require('../models/sessionModel');
const logger = require('../utils/logger');
require('dotenv').config();

// Enhanced authentication middleware that supports both JWT and session tokens
exports.authenticate = async (req, res, next) => {
    try {
        let user = null;
        let authMethod = null;

        // Check for session token in cookies first
        const sessionToken = req.cookies.sessionToken;
        if (sessionToken) {
            const session = await Session.findOne({
                sessionToken,
                isActive: true,
                expiresAt: { $gt: new Date() }
            }).populate('userId');

            if (session && session.userId) {
                user = session.userId;
                authMethod = 'session';
                
                // Update last accessed time
                session.lastAccessed = new Date();
                await session.save();
            }
        }

        // If no valid session, check for JWT token
        if (!user) {
            const authHeader = req.headers.authorization;
            const jwtToken = authHeader?.split(' ')[1] || req.cookies.authToken;
            
            if (jwtToken) {
                try {
                    const decoded = jwt.verify(jwtToken, process.env.SECRET_KEY);
                    user = await User.findById(decoded._id).select('-password -resetToken -resetTokenExpiry -refreshToken');
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

// Admin verification middleware
exports.verifyAdmin = async (req, res, next) => {
    try {
        // First authenticate the user
        await new Promise((resolve, reject) => {
            exports.authenticate(req, res, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        // Check if user has admin role
        if (req.user.role !== 'admin' && req.user.role !== 'Admin') {
            logger.warn(`Non-admin user ${req.user.email} attempted to access admin route`);
            return res.status(403).json({ 
                status: 'FAILED',
                message: 'Forbidden: Admin access required' 
            });
        }

        next();
    } catch (error) {
        return res.status(401).json({ 
            status: 'FAILED',
            message: 'Authentication failed!' 
        });
    }
};

// Optional authentication middleware (doesn't fail if not authenticated)
exports.optionalAuth = async (req, res, next) => {
    try {
        // Try to authenticate but don't fail if no token
        const sessionToken = req.cookies.sessionToken;
        const authHeader = req.headers.authorization;
        const jwtToken = authHeader?.split(' ')[1] || req.cookies.authToken;

        if (sessionToken) {
            const session = await Session.findOne({
                sessionToken,
                isActive: true,
                expiresAt: { $gt: new Date() }
            }).populate('userId');

            if (session && session.userId) {
                req.user = session.userId;
                req.authMethod = 'session';
                
                session.lastAccessed = new Date();
                await session.save();
            }
        } else if (jwtToken) {
            try {
                const decoded = jwt.verify(jwtToken, process.env.SECRET_KEY);
                const user = await User.findById(decoded._id).select('-password -resetToken -resetTokenExpiry -refreshToken');
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

// Enhanced rate limiting middleware for login attempts
exports.loginRateLimit = (() => {
    const attempts = new Map();
    const MAX_ATTEMPTS = 5;
    const WINDOW_MS = 15 * 60 * 1000; // 15 minutes

    // Cleanup old entries periodically
    setInterval(() => {
        const now = Date.now();
        for (const [ip, data] of attempts.entries()) {
            if (now - data.firstAttempt > WINDOW_MS) {
                attempts.delete(ip);
            }
        }
    }, 5 * 60 * 1000); // Clean up every 5 minutes

    return (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress;
        const now = Date.now();
        
        if (!attempts.has(ip)) {
            attempts.set(ip, { count: 1, firstAttempt: now });
            return next();
        }

        const userAttempts = attempts.get(ip);
        
        // Reset if window has passed
        if (now - userAttempts.firstAttempt > WINDOW_MS) {
            attempts.set(ip, { count: 1, firstAttempt: now });
            return next();
        }

        // Check if max attempts exceeded
        if (userAttempts.count >= MAX_ATTEMPTS) {
            const remainingTime = Math.ceil((WINDOW_MS - (now - userAttempts.firstAttempt)) / 1000);
            logger.warn(`Rate limit exceeded for IP: ${ip}`);
            
            return res.status(429).json({
                status: 'FAILED',
                message: 'Too many login attempts. Please try again later.',
                retryAfter: remainingTime
            });
        }

        // Increment attempt count
        userAttempts.count++;
        next();
    };
})();

// CSRF protection middleware
exports.csrfProtection = (req, res, next) => {
    // Skip CSRF for GET requests and certain API endpoints
    if (req.method === 'GET' || req.path.includes('/api/auth/verify')) {
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

// Middleware to check if session is about to expire and refresh if needed
exports.refreshSession = async (req, res, next) => {
    try {
        const sessionToken = req.cookies.sessionToken;
        
        if (sessionToken && req.user && req.authMethod === 'session') {
            const session = await Session.findOne({ sessionToken });
            
            if (session) {
                const timeUntilExpiry = session.expiresAt - new Date();
                const refreshThreshold = 2 * 60 * 60 * 1000; // 2 hours
                
                // If session expires in less than 2 hours, extend it
                if (timeUntilExpiry < refreshThreshold) {
                    session.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // Extend by 24 hours
                    await session.save();
                    
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

// Request logging middleware
exports.requestLogger = (req, res, next) => {
    const start = Date.now();
    
    // Log response after it's sent
    res.on('finish', () => {
        const duration = Date.now() - start;
        const logData = {
            method: req.method,
            url: req.originalUrl || req.url,
            status: res.statusCode,
            duration: `${duration}ms`,
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent'),
            user: req.user?.email || 'anonymous'
        };
        
        if (res.statusCode >= 400) {
            logger.error('Request failed:', logData);
        } else {
            logger.info('Request completed:', logData);
        }
    });
    
    next();
};

// Security headers middleware
exports.securityHeaders = (req, res, next) => {
    // Add security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    
    // Remove sensitive headers
    res.removeHeader('X-Powered-By');
    
    next();
};

// API versioning middleware
exports.apiVersion = (version) => {
    return (req, res, next) => {
        req.apiVersion = version;
        res.setHeader('X-API-Version', version);
        next();
    };
};

// Pagination middleware
exports.paginate = (req, res, next) => {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 100); // Max 100 items per page
    const skip = (page - 1) * limit;
    
    req.pagination = {
        page,
        limit,
        skip
    };
    
    next();
};