const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
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

require('dotenv').config();

// Enhanced configuration with no hardcoded fallbacks
const config = {
    jwt: {
        secret: process.env.SECRET_KEY,
        expiresIn: process.env.JWT_EXPIRES_IN || '1d',
        refreshSecret: process.env.REFRESH_SECRET,
        refreshExpiresIn: process.env.REFRESH_EXPIRES_IN || '30d'
    },
    email: {
        host: process.env.AUTH_EMAIL,
        password: process.env.AUTH_PASSWORD
    },
    session: {
        secret: process.env.SESSION_SECRET
    },
    baseUrl: process.env.NODE_ENV === 'production'
        ? process.env.BASE_URL_PRODUCTION || 'https://circlemate-spark-landing-jet.vercel.app'
        : process.env.BASE_URL_DEVELOPMENT || 'http://localhost:3000'
};

// Validate required environment variables
const validateEnvVars = () => {
    const required = ['SECRET_KEY', 'AUTH_EMAIL', 'AUTH_PASSWORD', 'SESSION_SECRET'];
    const missing = required.filter(key => !process.env[key]);
    
    if (missing.length > 0) {
        throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
    }
};

// Call validation on startup
validateEnvVars();

// Cookie configuration
const getCookieOptions = (rememberMe = false) => ({
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
    maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
    path: '/'
});

// Enhanced NODEMAILER TRANSPORTER with better error handling
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: config.email.host,
        pass: config.email.password,
    },
    pool: true,
    maxConnections: 5,
    maxMessages: 10
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
    return crypto.createHash('sha256').update(`${timestamp}-${random}-${userId}`).digest('hex');
};

// Enhanced session creation with race condition prevention
const createSession = async (userId, userAgent, ipAddress) => {
    try {
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

        const sessionToken = generateSessionToken();
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

        const session = new Session({
            sessionToken,
            userId,
            userAgent: userAgent || 'Unknown',
            ipAddress: ipAddress || 'Unknown',
            expiresAt,
            isActive: true
        });

        await session.save();
        
        logger.info(`Session created for user ${userId} from IP ${ipAddress}`);
        return sessionToken;
    } catch (error) {
        logger.error('Error creating session:', error);
        throw new Error('Failed to create session');
    }
};

// HELPER: VALIDATE SESSION
const validateSession = async (sessionToken) => {
    try {
        const session = await Session.findOne({
            sessionToken,
            isActive: true,
            expiresAt: { $gt: new Date() }
        }).populate('userId');

        if (!session) {
            return null;
        }

        // Update last accessed time
        session.lastAccessed = new Date();
        await session.save();

        return session;
    } catch (error) {
        logger.error('Error validating session:', error);
        return null;
    }
};

// HELPER: INVALIDATE SESSION
const invalidateSession = async (sessionToken) => {
    try {
        await Session.updateOne(
            { sessionToken },
            { 
                isActive: false,
                loggedOutAt: new Date()
            }
        );
        logger.info(`Session ${sessionToken} invalidated`);
    } catch (error) {
        logger.error('Error invalidating session:', error);
    }
};

// HELPER: CLEANUP EXPIRED SESSIONS
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

// Enhanced email sending with retry logic
const sendVerificationEmail = async ({ _id, email }, retries = 3) => {
    try {
        const currentUrl = `${config.baseUrl}/api/auth/verify/`;
        const uniqueString = `${uuidv4()}${_id}`;
        const hashedUniqueString = await bcrypt.hash(uniqueString, 10);

        await new UserVerification({
            userId: _id,
            uniqueString: hashedUniqueString,
            createdAt: Date.now(),
            expiresAt: Date.now() + 6 * 60 * 60 * 1000,
        }).save();

        const mailOptions = {
            from: config.email.host,
            to: email,
            subject: 'Verify Your Email',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">Email Verification</h2>
                    <p>Thank you for signing up! Please verify your email address to complete the registration process.</p>
                    <p>This verification link will <strong>expire in 6 hours</strong>.</p>
                    <div style="margin: 30px 0;">
                        <a href="${currentUrl}${_id}/${uniqueString}" 
                           style="background-color: #4CAF50; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; display: inline-block;">
                            Verify Email Address
                        </a>
                    </div>
                    <p style="color: #666; font-size: 14px;">If you didn't create an account, please ignore this email.</p>
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

// Generate tokens (both access and refresh)
const generateTokens = (userId) => {
    const accessToken = jwt.sign(
        { _id: userId },
        config.jwt.secret,
        { expiresIn: config.jwt.expiresIn }
    );
    
    const refreshToken = jwt.sign(
        { _id: userId },
        config.jwt.refreshSecret || config.jwt.secret,
        { expiresIn: config.jwt.refreshExpiresIn }
    );
    
    return { accessToken, refreshToken };
};

// Track failed login attempts
const trackFailedLogin = async (email, ipAddress) => {
    try {
        const user = await User.findOne({ email });
        if (user) {
            user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
            user.lastFailedLogin = new Date();
            
            // Lock account after 5 failed attempts
            if (user.failedLoginAttempts >= 5) {
                user.accountLockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
                logger.warn(`Account locked for user: ${email} due to multiple failed login attempts`);
            }
            
            await user.save();
        }
        
        // Log the failed attempt
        logger.warn(`Failed login attempt for email: ${email} from IP: ${ipAddress}`);
    } catch (error) {
        logger.error('Error tracking failed login:', error);
    }
};

// Reset failed login attempts
const resetFailedLoginAttempts = async (userId) => {
    try {
        await User.updateOne(
            { _id: userId },
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

// VERIFY EMAIL ROUTE
exports.verifyEmail = async (req, res) => {
    const { userId, uniqueString } = req.params;

    try {
        logger.info(`Email verification attempt for user: ${userId}`); // Add this log
        
        const user = await User.findById(userId);
        if (user && user.verified) {
            logger.info(`User ${userId} is already verified`); // Add this log
            return res.redirect(`/api/verified?success=true&message=User is already verified.`);
        }

        const record = await UserVerification.findOne({ userId });
        if (!record) {
            logger.warn(`No verification record found for user: ${userId}`); // Add this log
            return res.redirect(`/api/verified?error=true&message=Invalid or expired link.`);
        }

        if (record.expiresAt < Date.now()) {
            await UserVerification.deleteOne({ userId });
            await User.deleteOne({ _id: userId });
            logger.warn(`Verification link expired for user: ${userId}`); // Add this log
            return res.redirect(`/api/verified?error=true&message=Link expired. Please sign up again.`);
        }

        const isValid = await bcrypt.compare(uniqueString, record.uniqueString);
        if (!isValid) {
            logger.warn(`Invalid verification string for user: ${userId}`); // Add this log
            return res.redirect(`/api/verified?error=true&message=Invalid verification details.`);
        }

        await User.updateOne({ _id: userId }, { verified: true });
        await UserVerification.deleteOne({ userId });
        
        logger.info(`User ${userId} successfully verified`); // Add this log
        
        return res.redirect(`/api/verified?success=true&message=Email verified successfully!`);
    } catch (error) {
        logger.error('Email verification error:', error); // Update this log
        res.redirect(`/api/verified?error=true&message=Verification failed. Please try again.`);
    }
};


// Add this new function to authController.js
exports.checkVerificationStatus = async (req, res, next) => {
    const { email } = req.params;
    
    try {
        // Validate email format
        if (!email || !email.includes('@')) {
            return res.status(400).json({
                status: 'FAILED',
                message: 'Invalid email format'
            });
        }
        
        const user = await User.findOne({ email: email.toLowerCase() });
        
        if (!user) {
            return res.status(404).json({
                status: 'FAILED',
                message: 'User not found'
            });
        }
        
        res.status(200).json({
            status: 'success',
            data: {
                email: user.email,
                verified: user.verified,
                userId: user._id
            }
        });
    } catch (error) {
        logger.error('Check verification status error:', error);
        next(error);
    }
};

// RESEND VERIFICATION EMAIL ROUTE
exports.resendVerificationEmail = async (req, res, next) => {
    const { email } = req.body;
    
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ status: 'FAILED', message: 'User not found.' });
        }
        
        if (user.verified) {
            return res.status(400).json({ status: 'FAILED', message: 'User is already verified.' });
        }
        
        const existingRecord = await UserVerification.findOne({ userId: user._id });
        
        if (existingRecord && existingRecord.expiresAt > Date.now()) {
            return res.status(400).json({
                status: 'FAILED',
                message: 'A verification link has already been sent and is still active. Please check your email.'
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

// Enhanced REGISTER USER with validation
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

        const existingUser = await User.findOne({ email: req.body.email });
        if (existingUser) {
            logger.info(`Signup attempt with existing email: ${req.body.email}`);
            return next(new createError('User already exists!', 400));
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 12);

        const newUser = await User.create({
            ...req.body,
            password: hashedPassword,
            verified: false,
        });

        logger.info(`New user created: ${newUser.email}`);
        const emailResponse = await sendVerificationEmail(newUser);

        res.status(201).json({
            status: emailResponse.status,
            message: emailResponse.message,
            user: {
                _id: newUser._id,
                userName: newUser.userName,
                firstName: newUser.firstName,
                lastName: newUser.lastName,
                email: newUser.email,
                role: newUser.role,
                verified: false,
            },
        });
    } catch (error) {
        logger.error('Signup error:', error);
        next(error);
    }
};

// Enhanced LOGIN with better security
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

        const user = await User.findOne({ email });
        const ipAddress = req.ip || req.connection.remoteAddress;

        // Generic error message for security
        const invalidCredentialsError = new createError('Invalid credentials.', 401);

        if (!user) {
            await trackFailedLogin(email, ipAddress);
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
            await trackFailedLogin(email, ipAddress);
            return next(invalidCredentialsError);
        }

        // Reset failed login attempts on successful login
        await resetFailedLoginAttempts(user._id);

        // Clean up expired sessions periodically
        await cleanupExpiredSessions();

        // Create new session
        const userAgent = req.get('User-Agent');
        const sessionToken = await createSession(user._id, userAgent, ipAddress);

        // Generate tokens
        const { accessToken, refreshToken } = generateTokens(user._id);

        // Store refresh token in database
        user.refreshToken = refreshToken;
        user.lastLoginAt = new Date();
        await user.save();

        // Set cookies
        const cookieOptions = getCookieOptions(rememberMe);
        res.cookie('sessionToken', sessionToken, cookieOptions);
        res.cookie('authToken', accessToken, cookieOptions);
        res.cookie('refreshToken', refreshToken, { ...cookieOptions, path: '/api/auth/refresh' });

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

// Refresh token endpoint
exports.refreshToken = async (req, res, next) => {
    try {
        const { refreshToken } = req.cookies;
        
        if (!refreshToken) {
            return res.status(401).json({
                status: 'FAILED',
                message: 'Refresh token not provided'
            });
        }

        const decoded = jwt.verify(refreshToken, config.jwt.refreshSecret || config.jwt.secret);
        const user = await User.findById(decoded._id);

        if (!user || user.refreshToken !== refreshToken) {
            return res.status(401).json({
                status: 'FAILED',
                message: 'Invalid refresh token'
            });
        }

        // Generate new tokens
        const { accessToken, refreshToken: newRefreshToken } = generateTokens(user._id);

        // Update refresh token in database
        user.refreshToken = newRefreshToken;
        await user.save();

        // Set new cookies
        const cookieOptions = getCookieOptions();
        res.cookie('authToken', accessToken, cookieOptions);
        res.cookie('refreshToken', newRefreshToken, { ...cookieOptions, path: '/api/auth/refresh' });

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

// Enhanced LOGOUT
exports.logout = async (req, res, next) => {
    try {
        const sessionToken = req.cookies.sessionToken;
        
        if (sessionToken) {
            await invalidateSession(sessionToken);
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
        res.clearCookie('refreshToken', { ...getCookieOptions(), path: '/api/auth/refresh' });

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

// GET CURRENT USER
exports.getCurrentUser = async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id).select('-password -resetToken -resetTokenExpiry -refreshToken');
        
        if (!user) {
            return res.status(404).json({
                status: 'FAILED',
                message: 'User not found.'
            });
        }

        res.status(200).json({
            status: 'success',
            user: {
                _id: user._id,
                userName: user._userName,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                role: user.role,
                verified: user.verified,
                fileUploadCount: user.fileUploadCount,
                ProcessedDocument: user.ProcessedDocument,
                lastLoginAt: user.lastLoginAt
            }
        });
    } catch (error) {
        next(error);
    }
};

// Enhanced LOGOUT FROM ALL DEVICES
exports.logoutAllDevices = async (req, res, next) => {
    try {
        const userId = req.user._id;
        
        // Invalidate all sessions for this user
        await Session.updateMany(
            { userId, isActive: true },
            { 
                isActive: false,
                loggedOutAt: new Date()
            }
        );

        // Clear refresh token
        await User.updateOne(
            { _id: userId },
            { $unset: { refreshToken: 1 } }
        );

        // Clear current cookies
        res.clearCookie('sessionToken', getCookieOptions());
        res.clearCookie('authToken', getCookieOptions());
        res.clearCookie('refreshToken', { ...getCookieOptions(), path: '/api/auth/refresh' });

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

// GET ACTIVE SESSIONS
exports.getActiveSessions = async (req, res, next) => {
    try {
        const userId = req.user._id;
        
        const sessions = await Session.find({
            userId,
            isActive: true,
            expiresAt: { $gt: new Date() }
        }).select('userAgent ipAddress createdAt lastAccessed');

        res.status(200).json({
            status: 'success',
            sessions: sessions.map(session => ({
                id: session._id,
                userAgent: session.userAgent,
                ipAddress: session.ipAddress,
                createdAt: session.createdAt,
                lastAccessed: session.lastAccessed,
                isCurrent: session.sessionToken === req.cookies.sessionToken
            }))
        });
    } catch (error) {
        next(error);
    }
};

// Enhanced FORGOT PASSWORD with rate limiting
exports.forgotPassword = async (req, res, next) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        
        // Always return success for security (don't reveal if email exists)
        const successResponse = {
            status: 'success',
            message: 'If an account exists with this email, a password reset link has been sent.'
        };

        if (!user) {
            logger.info(`Password reset attempted for non-existent email: ${email}`);
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

        user.resetToken = hashedToken;
        user.resetTokenExpiry = resetTokenExpiry;
        user.lastPasswordResetRequest = Date.now();
        await user.save();

        const resetURL = `${config.baseUrl}/api/auth/reset-password/${resetToken}`;
        
        await transporter.sendMail({
            from: config.email.host,
            to: email,
            subject: 'Password Reset Request',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">Password Reset Request</h2>
                    <p>Hi ${user.userName},</p>
                    <p>We received a request to reset your password. Click the link below to set a new password:</p>
                    <div style="margin: 30px 0;">
                        <a href="${resetURL}" 
                           style="background-color: #4CAF50; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; display: inline-block;">
                            Reset Password
                        </a>
                    </div>
                    <p style="color: #666;">This link expires in 10 minutes.</p>
                    <p style="color: #666;">If you didn't request this, please ignore this email and your password will remain unchanged.</p>
                </div>
            `,
        });

        logger.info(`Password reset email sent to: ${email}`);
        res.status(200).json(successResponse);
    } catch (error) {
        logger.error('Password reset error:', error);
        next(error);
    }
};

// Enhanced RESET PASSWORD
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

        const user = await User.findOne({
            resetToken: { $exists: true },
            resetTokenExpiry: { $gt: Date.now() },
        });

        if (!user || !(await bcrypt.compare(token, user.resetToken))) {
            return res.sendFile(path.join(__dirname, '../views/reset-error.html'));
        }

        // Update password and clear reset token
        user.password = await bcrypt.hash(newPassword, 12);
        user.resetToken = undefined;
        user.resetTokenExpiry = undefined;
        user.lastPasswordResetRequest = undefined;
        user.passwordChangedAt = Date.now();
        await user.save();

        // Invalidate all existing sessions for security
        await Session.updateMany(
            { userId: user._id, isActive: true },
            { 
                isActive: false,
                loggedOutAt: new Date()
            }
        );

        // Send confirmation email
        await transporter.sendMail({
            from: config.email.host,
            to: user.email,
            subject: 'Password Changed Successfully',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">Password Changed</h2>
                    <p>Hi ${user.userName},</p>
                    <p>Your password has been successfully changed.</p>
                    <p style="color: #666;">If you didn't make this change, please contact support immediately.</p>
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

// FETCH ALL USERS (Admin only)
exports.getAllUsers = async (req, res, next) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const skip = (page - 1) * limit;

        const users = await User.find({})
            .select('-password -resetToken -resetTokenExpiry -refreshToken')
            .skip(skip)
            .limit(limit)
            .sort({ createdAt: -1 });

        const total = await User.countDocuments();

        res.status(200).json({
            status: 'success',
            data: {
                users,
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

// Export session validation helper for middleware
exports.validateSession = validateSession;