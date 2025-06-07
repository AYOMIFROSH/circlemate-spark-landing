const express = require('express');
const authController = require('../controllers/authController');
const path = require('path');
const User = require('../models/userModel');
const bcrypt = require('bcryptjs');
const { 
    authenticate, 
    verifyAdmin, 
    optionalAuth, 
    loginRateLimit, 
    refreshSession 
} = require('./middleware');

const router = express.Router();

// Public routes (no authentication required)
router.post('/signup', authController.signup);
router.post('/login', loginRateLimit, authController.login);
router.post('/forgotpassword', authController.forgotPassword);
router.post('/resend-verification', authController.resendVerificationEmail);
router.get('/check-verification/:email', authController.checkVerificationStatus);

// Email verification route
router.get('/verify/:userId/:uniqueString', authController.verifyEmail);

// Password reset routes
router.get('/reset-password/:token', async (req, res) => {
    const { token } = req.params;

    try {
        const user = await User.findOne({
            resetToken: { $exists: true },
            resetTokenExpiry: { $gt: Date.now() },
        });

        if (!user || !(await bcrypt.compare(token, user.resetToken))) {
            return res.sendFile(path.join(__dirname, '../views/reset-success.html'));
        }

        res.render('reset-password', { token });
    } catch (error) {
        console.error('Error verifying reset link:', error);
        res.status(500).json({ message: 'An error occurred. Please try again.' });
    }
});

router.post('/reset-password/:token', authController.resetPassword);

// Protected routes (authentication required)
router.use(authenticate); // Apply authentication to all routes below
router.use(refreshSession); // Auto-refresh sessions when needed

// User profile and session management
router.get('/me', authController.getCurrentUser);
router.post('/logout', authController.logout);
router.post('/logout-all', authController.logoutAllDevices);
router.get('/sessions', authController.getActiveSessions);

// Admin-only routes
router.get('/users', verifyAdmin, authController.getAllUsers);

// Health check endpoint (with optional auth to show user info if logged in)
router.get('/health', optionalAuth, (req, res) => {
    res.status(200).json({
        status: 'success',
        message: 'Authentication service is running',
        timestamp: new Date().toISOString(),
        user: req.user ? {
            id: req.user._id,
            email: req.user.email,
            role: req.user.role,
            authMethod: req.authMethod
        } : null
    });
});

// Session validation endpoint
router.get('/validate-session', (req, res) => {
    // If middleware passes, session is valid
    res.status(200).json({
        status: 'success',
        message: 'Session is valid',
        user: {
            _id: req.user._id,
            userName: req.user.userName,
            email: req.user.email,
            role: req.user.role,
            verified: req.user.verified
        },
        authMethod: req.authMethod
    });
});

module.exports = router;