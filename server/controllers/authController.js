const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid'); 
const crypto = require('crypto');
const path = require('path');
const User = require('../models/userModel');
const UserVerification = require('../models/UserVerification');
const Session = require('../models/sessionModel'); 
const createError = require('../utils/appError');
const logger = require('../utils/logger');
const { validateSignup, validateLogin, validatePasswordReset } = require('../utils/inputValidation');
const redis = require('../utils/redis'); // Add Redis client

require('dotenv').config();

// Enhanced configuration with no hardcoded fallbacks
const config = {
    jwt: {
        secret: process.env.SECRET_KEY,
        algorithm: 'HS256', // Explicitly specify algorithm
        expiresIn: process.env.JWT_EXPIRES_IN || '15m', // Reduced from 1d for security
        refreshSecret: process.env.REFRESH_SECRET,
        refreshExpiresIn: process.env.REFRESH_EXPIRES_IN || '7d', // Reduced from 30d
        issuer: 'circlemate',
        audience: 'circlemate-users'
    },
    email: {
        host: process.env.AUTH_EMAIL,
        password: process.env.AUTH_PASSWORD
    },
    session: {
        secret: process.env.SESSION_SECRET,
        maxConcurrentSessions: 5 // Limit concurrent sessions per user
    },
    security: {
        bcryptRounds: 12,
        maxLoginAttempts: 5,
        lockoutDuration: 30 * 60 * 1000, // 30 minutes
        tokenBlacklistPrefix: 'blacklist:token:'
    },
    baseUrl: process.env.NODE_ENV === 'production'
        ? process.env.BASE_URL_PRODUCTION || 'https://circlemate-spark-landing-jet.vercel.app'
        : process.env.BASE_URL_DEVELOPMENT || 'http://localhost:3000'
};

// Validate required environment variables
const validateEnvVars = () => {
    const required = ['SECRET_KEY', 'AUTH_EMAIL', 'AUTH_PASSWORD', 'SESSION_SECRET', 'REFRESH_SECRET'];
    const missing = required.filter(key => !process.env[key]);
    
    if (missing.length > 0) {
        throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
    }
};

// Call validation on startup
validateEnvVars();

// Cookie configuration with enhanced security
const getCookieOptions = (rememberMe = false) => ({
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
    maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000, // Reduced from 30 days
    path: '/',
    domain: process.env.COOKIE_DOMAIN || undefined // Allow subdomain sharing if needed
});

// Enhanced NODEMAILER TRANSPORTER with connection pooling
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: config.email.host,
        pass: config.email.password,
    },
    pool: true,
    maxConnections: 5,
    maxMessages: 10,
    rateDelta: 1000, // Rate limiting for email sending
    rateLimit: 5 // Max 5 emails per second
});

// Verify transporter configuration
transporter.verify((error, success) => {
    if (error) {
        logger.error('Email transporter error:', error);
    } else {
        logger.info('Email server is ready');
    }
});

// Enhanced session token generation with more entropy
const generateSessionToken = () => {
    const timestamp = Date.now().toString();
    const random = crypto.randomBytes(32).toString('hex');
    const userId = crypto.randomBytes(16).toString('hex');
    const processId = process.pid.toString();
    return crypto.createHash('sha256').update(`${timestamp}-${random}-${userId}-${processId}`).digest('hex');
};

// Enhanced session creation with race condition prevention and session limiting
// Replace the createSession function in your authController.js with this:
const createSession = async (userId, userAgent, ipAddress) => {
    try {
        let sessionToken;
        let newSession;
        
        // Start a transaction to prevent race conditions
        const mongooseSession = await mongoose.startSession();
        
        await mongooseSession.withTransaction(async () => {
            // Count active sessions for the user
            const activeSessions = await Session.countDocuments({ 
                userId, 
                isActive: true,
                expiresAt: { $gt: new Date() }
            });

            // If user has too many active sessions, invalidate the oldest one
            if (activeSessions >= config.session.maxConcurrentSessions) {
                const oldestSession = await Session.findOne({ 
                    userId, 
                    isActive: true 
                }).sort({ createdAt: 1 });
                
                if (oldestSession) {
                    oldestSession.isActive = false;
                    oldestSession.loggedOutAt = new Date();
                    await oldestSession.save();
                    
                    // Clear Redis cache for old session
                    if (oldestSession.sessionToken) {
                        await redis.del(`session:${oldestSession.sessionToken}`);
                        await redis.del(`session:lastupdate:${oldestSession.sessionToken}`);
                    }
                    
                    logger.info(`Invalidated oldest session for user ${userId} due to session limit`);
                }
            }

            // Invalidate existing sessions for this user/device combination
            await Session.updateMany(
                { 
                    userId, 
                    userAgent, 
                    isActive: true 
                },
                { 
                    isActive: false,
                    loggedOutAt: new Date()
                }
            );

            // Generate session token
            sessionToken = generateSessionToken();
            const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

            // Create new session
            newSession = new Session({
                sessionToken,
                userId,
                userAgent: userAgent || 'Unknown',
                ipAddress: ipAddress || 'Unknown',
                expiresAt,
                isActive: true,
                deviceFingerprint: crypto.createHash('md5').update((userAgent || '') + (ipAddress || '')).digest('hex')
            });

            await newSession.save({ session: mongooseSession });
        });
        
        mongooseSession.endSession();
        
        // Cache session in Redis after successful transaction
        if (sessionToken && newSession) {
            await redis.setex(
                `session:${sessionToken}`,
                86400, // 24 hours
                JSON.stringify({
                    userId: userId.toString(),
                    sessionId: newSession._id.toString(),
                    expiresAt: newSession.expiresAt.toISOString()
                })
            );
        }
        
        logger.info(`Session created for user ${userId} from IP ${ipAddress}`);
        return sessionToken;
    } catch (error) {
        logger.error('Error creating session:', error);
        throw new Error('Failed to create session');
    }
};

// HELPER: VALIDATE SESSION with caching
const validateSession = async (sessionToken) => {
    try {
        // Check cache first
        const cacheKey = `session:${sessionToken}`;
        const cachedSession = await redis.get(cacheKey);
        
        if (cachedSession) {
            return JSON.parse(cachedSession);
        }

        const session = await Session.findOne({
            sessionToken,
            isActive: true,
            expiresAt: { $gt: new Date() }
        }).populate('userId').lean();

        if (!session) {
            return null;
        }

        // Update last accessed time (throttled to once per minute)
        const lastUpdate = await redis.get(`session:lastupdate:${sessionToken}`);
        if (!lastUpdate) {
            await Session.updateOne(
                { sessionToken },
                { lastAccessed: new Date() }
            );
            await redis.setex(`session:lastupdate:${sessionToken}`, 60, 'true');
        }

        // Cache the session for 5 minutes
        await redis.setex(cacheKey, 300, JSON.stringify(session));

        return session;
    } catch (error) {
        logger.error('Error validating session:', error);
        return null;
    }
};

// HELPER: INVALIDATE SESSION with cache cleanup
const invalidateSession = async (sessionToken) => {
    try {
        await Session.updateOne(
            { sessionToken },
            { 
                isActive: false,
                loggedOutAt: new Date()
            }
        );
        
        // Clear cache
        await redis.del(`session:${sessionToken}`);
        await redis.del(`session:lastupdate:${sessionToken}`);
        
        logger.info(`Session ${sessionToken} invalidated`);
    } catch (error) {
        logger.error('Error invalidating session:', error);
    }
};

// HELPER: CLEANUP EXPIRED SESSIONS (moved to a scheduled job)
const cleanupExpiredSessions = async () => {
    try {
        const result = await Session.deleteMany({
            $or: [
                { expiresAt: { $lt: new Date() } },
                { isActive: false, loggedOutAt: { $lt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } }
            ]
        });
        logger.info(`Cleaned up ${result.deletedCount} expired sessions`);
    } catch (error) {
        logger.error('Error cleaning up expired sessions:', error);
    }
};

// Enhanced email sending with template support and retry logic
const sendVerificationEmail = async ({ _id, email }, retries = 3) => {
    try {
        const currentUrl = `${config.baseUrl}/api/v1/auth/verify/`;
        const uniqueString = `${uuidv4()}${_id}`;
        const hashedUniqueString = await bcrypt.hash(uniqueString, 10);

        // Use transaction to ensure atomicity
        const session = await mongoose.startSession();
        await session.withTransaction(async () => {
            // Delete any existing verification records
            await UserVerification.deleteMany({ userId: _id });

            await new UserVerification({
                userId: _id,
                uniqueString: hashedUniqueString,
                createdAt: Date.now(),
                expiresAt: Date.now() + 6 * 60 * 60 * 1000,
            }).save();
        });

        const mailOptions = {
            from: `CircleMate <${config.email.host}>`,
            to: email,
            subject: 'Verify Your Email - CircleMate',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <h1 style="color: #4CAF50; margin: 0;">CircleMate</h1>
                        <p style="color: #666; margin-top: 5px;">Connect with your community</p>
                    </div>
                    
                    <div style="background-color: #f9f9f9; border-radius: 8px; padding: 30px;">
                        <h2 style="color: #333; margin-top: 0;">Email Verification</h2>
                        <p style="color: #555; line-height: 1.6;">
                            Thank you for signing up! Please verify your email address to complete the registration process.
                        </p>
                        <p style="color: #555; line-height: 1.6;">
                            This verification link will <strong>expire in 6 hours</strong>.
                        </p>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="${currentUrl}${_id}/${uniqueString}" 
                               style="background-color: #4CAF50; color: white; padding: 14px 30px; text-decoration: none; border-radius: 25px; display: inline-block; font-weight: 500;">
                                Verify Email Address
                            </a>
                        </div>
                        
                        <p style="color: #999; font-size: 14px; text-align: center;">
                            If the button doesn't work, copy and paste this link into your browser:
                        </p>
                        <p style="color: #999; font-size: 12px; text-align: center; word-break: break-all;">
                            ${currentUrl}${_id}/${uniqueString}
                        </p>
                    </div>
                    
                    <p style="color: #999; font-size: 12px; text-align: center; margin-top: 20px;">
                        If you didn't create an account, please ignore this email.
                    </p>
                </div>
            `,
        };

        logger.info(`Sending verification email to: ${email}`);
        await transporter.sendMail(mailOptions);
        logger.info(`Verification email sent successfully to: ${email}`);

        return { status: 'PENDING', message: 'Verification email sent!' };
    } catch (error) {
        logger.error(`Failed to send verification email to ${email}:`, error);
        
        if (retries > 0) {
            logger.info(`Retrying email send... ${retries} attempts left`);
            await new Promise(resolve => setTimeout(resolve, 2000));
            return sendVerificationEmail({ _id, email }, retries - 1);
        }
        
        throw new Error('Failed to send verification email. Please try again later.');
    }
};

// Generate tokens with enhanced security
const generateTokens = (userId) => {
    const tokenId = uuidv4(); // Add unique ID to each token for blacklisting
    
    const accessToken = jwt.sign(
        { 
            _id: userId,
            tokenId,
            type: 'access'
        },
        config.jwt.secret,
        { 
            expiresIn: config.jwt.expiresIn,
            algorithm: config.jwt.algorithm,
            issuer: config.jwt.issuer,
            audience: config.jwt.audience
        }
    );
    
    const refreshToken = jwt.sign(
        { 
            _id: userId,
            tokenId: uuidv4(), // Different ID for refresh token
            type: 'refresh'
        },
        config.jwt.refreshSecret || config.jwt.secret,
        { 
            expiresIn: config.jwt.refreshExpiresIn,
            algorithm: config.jwt.algorithm,
            issuer: config.jwt.issuer,
            audience: config.jwt.audience
        }
    );
    
    return { accessToken, refreshToken };
};

// Token blacklisting for secure logout
const blacklistToken = async (token) => {
    try {
        const decoded = jwt.decode(token);
        if (!decoded || !decoded.tokenId) return;
        
        const ttl = decoded.exp - Math.floor(Date.now() / 1000);
        if (ttl > 0) {
            await redis.setex(
                `${config.security.tokenBlacklistPrefix}${decoded.tokenId}`, 
                ttl, 
                'true'
            );
        }
    } catch (error) {
        logger.error('Error blacklisting token:', error);
    }
};

// Check if token is blacklisted
const isTokenBlacklisted = async (tokenId) => {
    const blacklisted = await redis.get(`${config.security.tokenBlacklistPrefix}${tokenId}`);
    return !!blacklisted;
};

// Enhanced failed login tracking with Redis
const trackFailedLogin = async (email, ipAddress) => {
    try {
        const key = `failed:login:${email}`;
        const ipKey = `failed:ip:${ipAddress}`;
        
        // Increment failed attempts
        const attempts = await redis.incr(key);
        await redis.expire(key, 900); // 15 minutes expiry
        
        // Track IP-based attempts
        const ipAttempts = await redis.incr(ipKey);
        await redis.expire(ipKey, 3600); // 1 hour expiry
        
        const user = await User.findOne({ email });
        if (user) {
            user.failedLoginAttempts = attempts;
            user.lastFailedLogin = new Date();
            
            // Lock account after threshold
            if (attempts >= config.security.maxLoginAttempts) {
                user.accountLockedUntil = new Date(Date.now() + config.security.lockoutDuration);
                logger.warn(`Account locked for user: ${email} due to multiple failed login attempts`);
            }
            
            await user.save();
        }
        
        logger.warn(`Failed login attempt ${attempts} for email: ${email} from IP: ${ipAddress}`);
        
        return { attempts, ipAttempts };
    } catch (error) {
        logger.error('Error tracking failed login:', error);
    }
};

// Reset failed login attempts
const resetFailedLoginAttempts = async (email) => {
    try {
        await redis.del(`failed:login:${email}`);
        await User.updateOne(
            { email },
            { 
                $set: { failedLoginAttempts: 0 },
                $unset: { accountLockedUntil: 1 }
            }
        );
    } catch (error) {
        logger.error('Error resetting failed login attempts:', error);
    }
};

exports.verifiedPage = (req, res) => {
    const { error, success, message } = req.query;
    
    logger.info('Verified page accessed with params:', { error, success, message });
    
    // Use EJS render since it's already configured
    res.render('verified', { 
        error: error === 'true',
        success: success === 'true',
        message: message || 'Verification completed successfully'
    });
};

// VERIFY EMAIL ROUTE with enhanced security
exports.verifyEmail = async (req, res) => {
    const { userId, uniqueString } = req.params;

    try {
        logger.info(`Email verification attempt for user: ${userId}`);
        
        // Validate MongoDB ObjectId format
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.redirect(`/api/verified?error=true&message=Invalid verification link.`);
        }
        
        const user = await User.findById(userId);
        if (user && user.verified) {
            logger.info(`User ${userId} is already verified`);
            return res.redirect(`/api/verified?success=true&message=User is already verified.`);
        }

        const record = await UserVerification.findOne({ userId });
        if (!record) {
            logger.warn(`No verification record found for user: ${userId}`);
            return res.redirect(`/api/verified?error=true&message=Invalid or expired link.`);
        }

        if (record.expiresAt < Date.now()) {
            await UserVerification.deleteOne({ userId });
            await User.deleteOne({ _id: userId });
            logger.warn(`Verification link expired for user: ${userId}`);
            return res.redirect(`/api/verified?error=true&message=Link expired. Please sign up again.`);
        }

        const isValid = await bcrypt.compare(uniqueString, record.uniqueString);
        if (!isValid) {
            logger.warn(`Invalid verification string for user: ${userId}`);
            return res.redirect(`/api/verified?error=true&message=Invalid verification details.`);
        }

        // Use transaction for atomic update
        const session = await mongoose.startSession();
        await session.withTransaction(async () => {
            await User.updateOne({ _id: userId }, { verified: true });
            await UserVerification.deleteOne({ userId });
        });
        
        logger.info(`User ${userId} successfully verified`);
        
        return res.redirect(`/api/verified?success=true&message=Email verified successfully!`);
    } catch (error) {
        logger.error('Email verification error:', error);
        res.redirect(`/api/verified?error=true&message=Verification failed. Please try again.`);
    }
};

// Check verification status with rate limiting
exports.checkVerificationStatus = async (req, res, next) => {
    const { email } = req.params;
    
    try {
        // Validate email format
        const emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
        if (!email || !emailRegex.test(email)) {
            return res.status(400).json({
                status: 'FAILED',
                message: 'Invalid email format'
            });
        }
        
        // Cache the result for 1 minute
        const cacheKey = `verification:status:${email.toLowerCase()}`;
        const cached = await redis.get(cacheKey);
        
        if (cached) {
            return res.status(200).json(JSON.parse(cached));
        }
        
        const user = await User.findOne({ email: email.toLowerCase() })
            .select('email verified _id')
            .lean();
        
        if (!user) {
            return res.status(404).json({
                status: 'FAILED',
                message: 'User not found'
            });
        }
        
        const response = {
            status: 'success',
            data: {
                email: user.email,
                verified: user.verified,
                userId: user._id
            }
        };
        
        // Cache for 1 minute
        await redis.setex(cacheKey, 60, JSON.stringify(response));
        
        res.status(200).json(response);
    } catch (error) {
        logger.error('Check verification status error:', error);
        next(error);
    }
};

// RESEND VERIFICATION EMAIL with rate limiting
exports.resendVerificationEmail = async (req, res, next) => {
    const { email } = req.body;
    
    try {
        // Check rate limit for resend requests
        const rateLimitKey = `resend:verification:${email}`;
        const attempts = await redis.incr(rateLimitKey);
        await redis.expire(rateLimitKey, 3600); // 1 hour window
        
        if (attempts > 3) {
            return res.status(429).json({
                status: 'FAILED',
                message: 'Too many resend attempts. Please try again later.'
            });
        }
        
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ status: 'FAILED', message: 'User not found.' });
        }
        
        if (user.verified) {
            return res.status(400).json({ status: 'FAILED', message: 'User is already verified.' });
        }
        
        const existingRecord = await UserVerification.findOne({ userId: user._id });
        
        if (existingRecord && existingRecord.expiresAt > Date.now()) {
            const timeRemaining = Math.ceil((existingRecord.expiresAt - Date.now()) / 60000);
            return res.status(400).json({
                status: 'FAILED',
                message: `A verification link is still active. Please check your email or wait ${timeRemaining} minutes.`
            });
        }
        
        if (existingRecord) {
            await UserVerification.deleteOne({ userId: user._id });
        }
        
        const emailResponse = await sendVerificationEmail({ _id: user._id, email: user.email });
        res.status(200).json({
            status: emailResponse.status,
            message: 'New verification link has been sent to your email.'
        });
    } catch (error) {
        logger.error('Resend verification error:', error);
        next(error);
    }
};

// Enhanced REGISTER USER with improved validation and security
exports.signup = async (req, res, next) => {
    try {
        // Validate input
        const validationErrors = await validateSignup(req.body);
        if (validationErrors) {
            return res.status(400).json({
                status: 'FAILED',
                message: 'Validation failed',
                errors: validationErrors
            });
        }

        // Normalize email
        const normalizedEmail = req.body.email.toLowerCase().trim();

        // Check for existing user with better index usage
        const existingUser = await User.findOne({ email: normalizedEmail }).select('_id').lean();
        if (existingUser) {
            logger.info(`Signup attempt with existing email: ${normalizedEmail}`);
            return next(new createError('User already exists!', 400));
        }

        // Enhanced password hashing
        const hashedPassword = await bcrypt.hash(req.body.password, config.security.bcryptRounds);

        // Use transaction for atomic user creation
        const session = await mongoose.startSession();
        let newUser;
        
        await session.withTransaction(async () => {
            newUser = await User.create([{
                ...req.body,
                email: normalizedEmail,
                password: hashedPassword,
                verified: false,
            }], { session });

            logger.info(`New user created: ${newUser[0].email}`);
        });

        const emailResponse = await sendVerificationEmail(newUser[0]);

        res.status(201).json({
            status: emailResponse.status,
            message: emailResponse.message,
            user: {
                _id: newUser[0]._id,
                userName: newUser[0].userName,
                firstName: newUser[0].firstName,
                lastName: newUser[0].lastName,
                email: newUser[0].email,
                role: newUser[0].role,
                verified: false,
            },
        });
    } catch (error) {
        logger.error('Signup error:', error);
        next(error);
    }
};

// Enhanced LOGIN with comprehensive security measures
exports.login = async (req, res, next) => {
    const { email, password, rememberMe } = req.body;

    try {
        // Validate input
        const validationErrors = await validateLogin(req.body);
        if (validationErrors) {
            return res.status(400).json({
                status: 'FAILED',
                message: 'Validation failed',
                errors: validationErrors
            });
        }

        const normalizedEmail = email.toLowerCase().trim();
        const ipAddress = req.ip || req.connection.remoteAddress;

        // Check IP-based rate limiting
        const ipAttempts = await redis.get(`failed:ip:${ipAddress}`);
        if (ipAttempts && parseInt(ipAttempts) > 20) {
            return res.status(429).json({
                status: 'FAILED',
                message: 'Too many login attempts from this IP. Please try again later.'
            });
        }

        // Generic error message for security
        const invalidCredentialsError = new createError('Invalid credentials.', 401);

        // Optimized user query with index
        const user = await User.findOne({ email: normalizedEmail })
            .select('+password +accountLockedUntil +failedLoginAttempts');

        if (!user) {
            await trackFailedLogin(normalizedEmail, ipAddress);
            return next(invalidCredentialsError);
        }

        // Check if account is locked
        if (user.accountLockedUntil && user.accountLockedUntil > new Date()) {
            const remainingTime = Math.ceil((user.accountLockedUntil - new Date()) / 1000 / 60);
            return res.status(423).json({
                status: 'FAILED',
                message: `Account is locked. Please try again in ${remainingTime} minutes.`
            });
        }

        if (!user.verified) {
            return res.status(401).json({
                status: 'FAILED',
                message: "Email hasn't been verified yet. Check your inbox.",
            });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            const { attempts } = await trackFailedLogin(normalizedEmail, ipAddress);
            const remainingAttempts = config.security.maxLoginAttempts - attempts;
            
            if (remainingAttempts > 0 && remainingAttempts <= 2) {
                return res.status(401).json({
                    status: 'FAILED',
                    message: `Invalid credentials. ${remainingAttempts} attempts remaining.`
                });
            }
            
            return next(invalidCredentialsError);
        }

        // Reset failed login attempts on successful login
        await resetFailedLoginAttempts(normalizedEmail);

        // Create new session
        const userAgent = req.get('User-Agent');
        const sessionToken = await createSession(user._id, userAgent, ipAddress);

        // Generate tokens
        const { accessToken, refreshToken } = generateTokens(user._id);

        // Store refresh token hash in database
        const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
        user.refreshToken = hashedRefreshToken;
        user.lastLoginAt = new Date();
        user.lastLoginIp = ipAddress;
        await user.save();

        // Set secure cookies
        const cookieOptions = getCookieOptions(rememberMe);
        res.cookie('sessionToken', sessionToken, cookieOptions);
        res.cookie('authToken', accessToken, cookieOptions);
        res.cookie('refreshToken', refreshToken, { 
            ...cookieOptions, 
            path: '/api/v1/auth/refresh',
            httpOnly: true 
        });

        logger.info(`User logged in successfully: ${user.email} from IP: ${ipAddress}`);

        res.status(200).json({
            status: 'success',
            message: 'Logged in successfully.',
            token: accessToken,
            sessionToken,
            user: {
                _id: user._id,
                userName: user.userName,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                role: user.role,
                verified: user.verified,
            },
        });
    } catch (error) {
        logger.error('Login error:', error);
        next(error);
    }
};

// Enhanced refresh token endpoint
exports.refreshToken = async (req, res, next) => {
    try {
        const { refreshToken } = req.cookies;
        
        if (!refreshToken) {
            return res.status(401).json({
                status: 'FAILED',
                message: 'Refresh token not provided'
            });
        }

        let decoded;
        try {
            decoded = jwt.verify(refreshToken, config.jwt.refreshSecret || config.jwt.secret, {
                algorithms: [config.jwt.algorithm],
                issuer: config.jwt.issuer,
                audience: config.jwt.audience
            });
        } catch (error) {
            return res.status(401).json({
                status: 'FAILED',
                message: 'Invalid refresh token'
            });
        }

        // Check if token is blacklisted
        if (await isTokenBlacklisted(decoded.tokenId)) {
            return res.status(401).json({
                status: 'FAILED',
                message: 'Token has been revoked'
            });
        }

        const user = await User.findById(decoded._id).select('+refreshToken');

        if (!user || !user.refreshToken) {
            return res.status(401).json({
                status: 'FAILED',
                message: 'Invalid refresh token'
            });
        }

        // Verify refresh token matches
        const isValidRefreshToken = await bcrypt.compare(refreshToken, user.refreshToken);
        if (!isValidRefreshToken) {
            return res.status(401).json({
                status: 'FAILED',
                message: 'Invalid refresh token'
            });
        }

        // Generate new tokens
        const { accessToken, refreshToken: newRefreshToken } = generateTokens(user._id);

        // Update refresh token in database
        const hashedNewRefreshToken = await bcrypt.hash(newRefreshToken, 10);
        user.refreshToken = hashedNewRefreshToken;
        await user.save();

        // Blacklist old refresh token
        await blacklistToken(refreshToken);

        // Set new cookies
        const cookieOptions = getCookieOptions();
        res.cookie('authToken', accessToken, cookieOptions);
        res.cookie('refreshToken', newRefreshToken, { 
            ...cookieOptions, 
            path: '/api/v1/auth/refresh',
            httpOnly: true 
        });

        res.status(200).json({
            status: 'success',
            message: 'Token refreshed successfully',
            token: accessToken
        });
    } catch (error) {
        logger.error('Token refresh error:', error);
        next(error);
    }
};

// Enhanced LOGOUT with token blacklisting
exports.logout = async (req, res, next) => {
    try {
        const sessionToken = req.cookies.sessionToken;
        const authToken = req.cookies.authToken;
        const refreshToken = req.cookies.refreshToken;
        
        // Invalidate session
        if (sessionToken) {
            await invalidateSession(sessionToken);
        }

        // Blacklist tokens
        if (authToken) {
            await blacklistToken(authToken);
        }
        if (refreshToken) {
            await blacklistToken(refreshToken);
        }

        // Clear refresh token from database
        if (req.user) {
            await User.updateOne(
                { _id: req.user._id },
                { $unset: { refreshToken: 1 } }
            );
        }

        // Clear all auth cookies
        res.clearCookie('sessionToken', getCookieOptions());
        res.clearCookie('authToken', getCookieOptions());
        res.clearCookie('refreshToken', { ...getCookieOptions(), path: '/api/v1/auth/refresh' });

        logger.info(`User logged out: ${req.user?.email}`);

        res.status(200).json({
            status: 'success',
            message: 'Logged out successfully.'
        });
    } catch (error) {
        logger.error('Logout error:', error);
        next(error);
    }
};

// GET CURRENT USER with caching
exports.getCurrentUser = async (req, res, next) => {
    try {
        // Check cache first
        const cacheKey = `user:${req.user._id}`;
        const cached = await redis.get(cacheKey);
        
        if (cached) {
            return res.status(200).json(JSON.parse(cached));
        }

        const user = await User.findById(req.user._id)
            .select('-password -resetToken -resetTokenExpiry -refreshToken -__v')
            .lean();
        
        if (!user) {
            return res.status(404).json({
                status: 'FAILED',
                message: 'User not found.'
            });
        }

        const response = {
            status: 'success',
            user: {
                _id: user._id,
                userName: user.userName,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                role: user.role,
                verified: user.verified,
                fileUploadCount: user.fileUploadCount,
                ProcessedDocument: user.ProcessedDocument,
                lastLoginAt: user.lastLoginAt,
                createdAt: user.createdAt
            }
        };

        // Cache for 5 minutes
        await redis.setex(cacheKey, 300, JSON.stringify(response));

        res.status(200).json(response);
    } catch (error) {
        next(error);
    }
};

// Enhanced LOGOUT FROM ALL DEVICES
exports.logoutAllDevices = async (req, res, next) => {
    try {
        const userId = req.user._id;
        
        // Start transaction
        const session = await mongoose.startSession();
        await session.withTransaction(async () => {
            // Invalidate all sessions for this user
            const sessions = await Session.find({ userId, isActive: true });
            
            // Blacklist all active tokens
            for (const userSession of sessions) {
                if (userSession.sessionToken) {
                    await redis.del(`session:${userSession.sessionToken}`);
                }
            }
            
            await Session.updateMany(
                { userId, isActive: true },
                { 
                    isActive: false,
                    loggedOutAt: new Date()
                }
            );

            // Clear refresh token and increment token version
            await User.updateOne(
                { _id: userId },
                { 
                    $unset: { refreshToken: 1 },
                    $inc: { tokenVersion: 1 } // This invalidates all existing tokens
                }
            );
        });

        // Clear current cookies
        res.clearCookie('sessionToken', getCookieOptions());
        res.clearCookie('authToken', getCookieOptions());
        res.clearCookie('refreshToken', { ...getCookieOptions(), path: '/api/v1/auth/refresh' });

        // Clear user cache
        await redis.del(`user:${userId}`);

        logger.info(`User logged out from all devices: ${req.user.email}`);

        res.status(200).json({
            status: 'success',
            message: 'Logged out from all devices successfully.'
        });
    } catch (error) {
        logger.error('Logout all devices error:', error);
        next(error);
    }
};

// GET ACTIVE SESSIONS with pagination
exports.getActiveSessions = async (req, res, next) => {
    try {
        const userId = req.user._id;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;
        
        const [sessions, total] = await Promise.all([
            Session.find({
                userId,
                isActive: true,
                expiresAt: { $gt: new Date() }
            })
            .select('userAgent ipAddress createdAt lastAccessed deviceFingerprint')
            .sort('-lastAccessed')
            .skip(skip)
            .limit(limit)
            .lean(),
            
            Session.countDocuments({
                userId,
                isActive: true,
                expiresAt: { $gt: new Date() }
            })
        ]);

        res.status(200).json({
            status: 'success',
            data: {
                sessions: sessions.map(session => ({
                    id: session._id,
                    userAgent: session.userAgent,
                    ipAddress: session.ipAddress,
                    createdAt: session.createdAt,
                    lastAccessed: session.lastAccessed,
                    isCurrent: session.sessionToken === req.cookies.sessionToken,
                    deviceInfo: parseUserAgent(session.userAgent)
                })),
                pagination: {
                    page,
                    limit,
                    total,
                    pages: Math.ceil(total / limit)
                }
            }
        });
    } catch (error) {
        next(error);
    }
};

// Enhanced FORGOT PASSWORD with better security
exports.forgotPassword = async (req, res, next) => {
    const { email } = req.body;

    try {
        const normalizedEmail = email.toLowerCase().trim();
        
        // Check rate limit
        const rateLimitKey = `forgot:password:${normalizedEmail}`;
        const attempts = await redis.incr(rateLimitKey);
        await redis.expire(rateLimitKey, 3600); // 1 hour window
        
        if (attempts > 3) {
            return res.status(429).json({
                status: 'FAILED',
                message: 'Too many password reset attempts. Please try again later.'
            });
        }
        
        const user = await User.findOne({ email: normalizedEmail });
        
        // Always return success for security (don't reveal if email exists)
        const successResponse = {
            status: 'success',
            message: 'If an account exists with this email, a password reset link has been sent.'
        };

        if (!user) {
            logger.info(`Password reset attempted for non-existent email: ${normalizedEmail}`);
            return res.status(200).json(successResponse);
        }

        // Check if a reset was recently requested
        if (user.lastPasswordResetRequest && 
            (Date.now() - user.lastPasswordResetRequest) < 60000) { // 1 minute
            return res.status(429).json({
                status: 'FAILED',
                message: 'Please wait before requesting another password reset.'
            });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = await bcrypt.hash(resetToken, 10);
        const resetTokenExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes

        // Use transaction
        const session = await mongoose.startSession();
        await session.withTransaction(async () => {
            user.resetToken = hashedToken;
            user.resetTokenExpiry = resetTokenExpiry;
            user.lastPasswordResetRequest = Date.now();
            await user.save({ session });
        });

        const resetURL = `${config.baseUrl}/api/v1/auth/reset-password/${resetToken}`;
        
        await transporter.sendMail({
            from: `CircleMate <${config.email.host}>`,
            to: normalizedEmail,
            subject: 'Password Reset Request - CircleMate',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <h1 style="color: #4CAF50; margin: 0;">CircleMate</h1>
                        <p style="color: #666; margin-top: 5px;">Password Reset Request</p>
                    </div>
                    
                    <div style="background-color: #f9f9f9; border-radius: 8px; padding: 30px;">
                        <p style="color: #555; line-height: 1.6;">Hi ${user.firstName || user.userName},</p>
                        <p style="color: #555; line-height: 1.6;">
                            We received a request to reset your password. Click the link below to set a new password:
                        </p>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="${resetURL}" 
                               style="background-color: #4CAF50; color: white; padding: 14px 30px; text-decoration: none; border-radius: 25px; display: inline-block; font-weight: 500;">
                                Reset Password
                            </a>
                        </div>
                        
                        <p style="color: #e74c3c; font-weight: bold;">
                            This link expires in 10 minutes for security reasons.
                        </p>
                        
                        <p style="color: #999; font-size: 14px;">
                            If the button doesn't work, copy and paste this link:
                        </p>
                        <p style="color: #999; font-size: 12px; word-break: break-all;">
                            ${resetURL}
                        </p>
                    </div>
                    
                    <div style="margin-top: 20px; padding: 20px; background-color: #fff3cd; border-radius: 8px;">
                        <p style="color: #856404; font-size: 14px; margin: 0;">
                            <strong>Security Note:</strong> If you didn't request this, please ignore this email 
                            and consider changing your password as a precaution.
                        </p>
                    </div>
                </div>
            `,
        });

        logger.info(`Password reset email sent to: ${normalizedEmail}`);
        res.status(200).json(successResponse);
    } catch (error) {
        logger.error('Password reset error:', error);
        next(error);
    }
};

// Enhanced RESET PASSWORD with additional security
exports.resetPassword = async (req, res) => {
    const { token } = req.params;
    const { newPassword, confirmPassword } = req.body;

    try {
        // Validate input
        const validationErrors = await validatePasswordReset({ newPassword, confirmPassword });
        if (validationErrors) {
            return res.status(400).json({
                status: 'FAILED',
                message: 'Validation failed',
                errors: validationErrors
            });
        }

        // Check if password is commonly used (basic check)
        const commonPasswords = ['password123', '12345678', 'qwerty123'];
        if (commonPasswords.includes(newPassword.toLowerCase())) {
            return res.status(400).json({
                status: 'FAILED',
                message: 'This password is too common. Please choose a stronger password.'
            });
        }

        const user = await User.findOne({
            resetToken: { $exists: true },
            resetTokenExpiry: { $gt: Date.now() },
        });

        if (!user || !(await bcrypt.compare(token, user.resetToken))) {
            return res.sendFile(path.join(__dirname, '../views/reset-error.html'));
        }

        // Check if new password is same as old password
        const isSamePassword = await bcrypt.compare(newPassword, user.password);
        if (isSamePassword) {
            return res.status(400).json({
                status: 'FAILED',
                message: 'New password must be different from your current password.'
            });
        }

        // Use transaction for atomic updates
        const session = await mongoose.startSession();
        await session.withTransaction(async () => {
            // Update password and clear reset token
            user.password = await bcrypt.hash(newPassword, config.security.bcryptRounds);
            user.resetToken = undefined;
            user.resetTokenExpiry = undefined;
            user.lastPasswordResetRequest = undefined;
            user.passwordChangedAt = Date.now();
            user.tokenVersion = (user.tokenVersion || 0) + 1; // Invalidate all tokens
            await user.save({ session });

            // Invalidate all existing sessions for security
            await Session.updateMany(
                { userId: user._id, isActive: true },
                { 
                    isActive: false,
                    loggedOutAt: new Date()
                },
                { session }
            );
        });

        // Clear user cache
        await redis.del(`user:${user._id}`);

        // Send confirmation email
        await transporter.sendMail({
            from: `CircleMate <${config.email.host}>`,
            to: user.email,
            subject: 'Password Changed Successfully - CircleMate',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <h1 style="color: #4CAF50; margin: 0;">CircleMate</h1>
                        <p style="color: #666; margin-top: 5px;">Password Changed</p>
                    </div>
                    
                    <div style="background-color: #f9f9f9; border-radius: 8px; padding: 30px;">
                        <p style="color: #555; line-height: 1.6;">Hi ${user.firstName || user.userName},</p>
                        <p style="color: #555; line-height: 1.6;">
                            Your password has been successfully changed at ${new Date().toLocaleString()}.
                        </p>
                        <p style="color: #555; line-height: 1.6;">
                            For security reasons, you have been logged out from all devices.
                        </p>
                    </div>
                    
                    <div style="margin-top: 20px; padding: 20px; background-color: #f8d7da; border-radius: 8px;">
                        <p style="color: #721c24; font-size: 14px; margin: 0;">
                            <strong>Didn't make this change?</strong> Your account may be compromised. 
                            Please contact support immediately at support@circlemate.com
                        </p>
                    </div>
                </div>
            `,
        });

        logger.info(`Password reset successfully for user: ${user.email}`);
        res.status(200).sendFile(path.join(__dirname, '../views/reset-success.html'));
    } catch (error) {
        logger.error('Error resetting password:', error);
        res.status(500).json({ message: 'Error resetting password. Please try again.' });
    }
};

// Enhanced FETCH ALL USERS with better performance
exports.getAllUsers = async (req, res, next) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 50, 100); // Max 100 per page
        const skip = (page - 1) * limit;
        const sort = req.query.sort || '-createdAt';
        const filter = {};

        // Add search functionality
        if (req.query.search) {
            filter.$or = [
                { email: { $regex: req.query.search, $options: 'i' } },
                { userName: { $regex: req.query.search, $options: 'i' } },
                { firstName: { $regex: req.query.search, $options: 'i' } },
                { lastName: { $regex: req.query.search, $options: 'i' } }
            ];
        }

        // Add role filter
        if (req.query.role) {
            filter.role = req.query.role;
        }

        // Add verification status filter
        if (req.query.verified !== undefined) {
            filter.verified = req.query.verified === 'true';
        }

        // Check cache for first page without filters
        const cacheKey = `users:page:${page}:limit:${limit}:sort:${sort}`;
        if (!req.query.search && !req.query.role && !req.query.verified && page === 1) {
            const cached = await redis.get(cacheKey);
            if (cached) {
                return res.status(200).json(JSON.parse(cached));
            }
        }

        const [users, total] = await Promise.all([
            User.find(filter)
                .select('-password -resetToken -resetTokenExpiry -refreshToken -__v')
                .skip(skip)
                .limit(limit)
                .sort(sort)
                .lean(),
            User.countDocuments(filter)
        ]);

        const response = {
            status: 'success',
            data: {
                users,
                pagination: {
                    page,
                    limit,
                    total,
                    pages: Math.ceil(total / limit),
                    hasNext: page < Math.ceil(total / limit),
                    hasPrev: page > 1
                }
            }
        };

        // Cache first page for 1 minute
        if (!req.query.search && !req.query.role && !req.query.verified && page === 1) {
            await redis.setex(cacheKey, 60, JSON.stringify(response));
        }

        res.status(200).json(response);
    } catch (error) {
        next(error);
    }
};

// Helper function to parse user agent
function parseUserAgent(userAgent) {
    if (!userAgent) return { browser: 'Unknown', os: 'Unknown' };
    
    // Simple parsing - can be enhanced with a library like 'useragent'
    let browser = 'Unknown';
    let os = 'Unknown';
    
    // Browser detection
    if (userAgent.includes('Chrome')) browser = 'Chrome';
    else if (userAgent.includes('Firefox')) browser = 'Firefox';
    else if (userAgent.includes('Safari')) browser = 'Safari';
    else if (userAgent.includes('Edge')) browser = 'Edge';
    
    // OS detection
    if (userAgent.includes('Windows')) os = 'Windows';
    else if (userAgent.includes('Mac')) os = 'macOS';
    else if (userAgent.includes('Linux')) os = 'Linux';
    else if (userAgent.includes('Android')) os = 'Android';
    else if (userAgent.includes('iOS')) os = 'iOS';
    
    return { browser, os };
}

// Schedule cleanup job (call this from your main app file)
if (!process.env.WORKER_NAME || process.env.WORKER_NAME === 'primary') {
    setInterval(cleanupExpiredSessions, 60 * 60 * 1000); // Run every hour
}

// Export session validation helper for middleware
exports.validateSession = validateSession;
exports.isTokenBlacklisted = isTokenBlacklisted;