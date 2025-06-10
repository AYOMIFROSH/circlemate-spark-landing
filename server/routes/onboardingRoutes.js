const express = require('express');
const onboardingController = require('../controllers/onboardingController');
const { authenticate, userBasedRateLimit, cacheResponse } = require('./middleware');
const { 
    validateCommunitySelection,
    validateProfileUpdate,
    validateLocation,
    validatePersonality,
    validatePreferences,
    validateAvailability
} = require('../utils/onboardingValidation');

const router = express.Router();

// All onboarding routes require authentication
router.use(authenticate);

// Apply user-based rate limiting to prevent abuse
router.use(userBasedRateLimit(100, 60000)); // 100 requests per minute

// Get onboarding status - Always accessible
router.get('/status', cacheResponse(3600), onboardingController.getOnboardingStatus);

// Get available communities - Always accessible
router.get('/communities', cacheResponse(3600), onboardingController.getCommunities);

// Each route is independent - order doesn't matter
// Users can complete these in any order they prefer

// Step 1: Community selection - Independent
router.post('/community', 
    validateCommunitySelection, 
    onboardingController.selectCommunity
);

// Step 2: Profile information - Independent
router.post('/profile', 
    validateProfileUpdate, 
    onboardingController.updateProfile
);

// Step 3: Location - Independent
router.post('/location', 
    validateLocation, 
    onboardingController.updateLocation
);

// Step 4: Personality traits - Independent
router.post('/personality', 
    validatePersonality, 
    onboardingController.updatePersonality
);

// Step 5: Preferences - Independent
router.post('/preferences', 
    validatePreferences, 
    onboardingController.updatePreferences
);

// Step 6: Availability - Independent
router.post('/availability', 
    validateAvailability, 
    onboardingController.updateAvailability
);

// Step 7: Photo upload - Independent (can be skipped)
router.post('/photos', onboardingController.uploadPhotos);
router.delete('/photos/:photoId', onboardingController.deletePhoto);

// Complete onboarding - Flexible completion
router.post('/complete', onboardingController.completeOnboarding);

// Additional utility routes

// Update single field endpoints for flexibility
router.patch('/profile/:field', async (req, res, next) => {
    try {
        const { field } = req.params;
        const allowedFields = ['bio', 'occupation', 'firstName', 'lastName'];
        
        if (!allowedFields.includes(field)) {
            return res.status(400).json({
                status: 'FAILED',
                message: `Field '${field}' is not allowed for single update`
            });
        }
        
        // Delegate to updateProfile with partial data
        req.body = { ...req.body, [field]: req.body[field] };
        next();
    } catch (error) {
        next(error);
    }
}, onboardingController.updateProfile);

// Skip onboarding endpoint for special cases
router.post('/skip', async (req, res, next) => {
    try {
        const { reason } = req.body;
        
        // Log the skip reason for analytics
        logger.info(`User ${req.user._id} skipped onboarding. Reason: ${reason || 'Not provided'}`);
        
        // Force complete the onboarding
        req.body.forceComplete = true;
        onboardingController.completeOnboarding(req, res, next);
    } catch (error) {
        next(error);
    }
});

// Get progress summary
router.get('/progress', cacheResponse(3600), async (req, res, next) => {
    try {
        const userId = req.user._id;
        const profile = await UserProfile.findOne({ userId }).lean();
        
        const progress = {
            community: !!(profile?.communities?.length > 0),
            profile: !!(profile?.firstName && profile?.lastName && profile?.age),
            location: !!(profile?.location?.city),
            personality: !!(profile?.personalityTraits?.length > 0),
            preferences: !!(profile?.connectionPurposes?.length > 0),
            availability: !!(profile?.availability?.days?.length > 0),
            photos: !!(profile?.profilePhotos?.length > 0)
        };
        
        const completed = Object.values(progress).filter(v => v).length;
        const total = Object.keys(progress).length;
        
        res.status(200).json({
            status: 'success',
            data: {
                progress,
                completed,
                total,
                percentage: Math.round((completed / total) * 100),
                canComplete: completed >= 2 // Minimum requirement
            }
        });
    } catch (error) {
        logger.error('Get progress error:', error);
        res.status(200).json({
            status: 'success',
            data: {
                progress: {},
                completed: 0,
                total: 7,
                percentage: 0,
                canComplete: false
            }
        });
    }
});

// Bulk update endpoint for efficiency
router.post('/bulk-update', async (req, res, next) => {
    try {
        const userId = req.user._id;
        const updates = req.body;
        const results = [];
        
        // Process each update independently
        const updateHandlers = {
            community: onboardingController.selectCommunity,
            profile: onboardingController.updateProfile,
            location: onboardingController.updateLocation,
            personality: onboardingController.updatePersonality,
            preferences: onboardingController.updatePreferences,
            availability: onboardingController.updateAvailability
        };
        
        for (const [key, data] of Object.entries(updates)) {
            if (updateHandlers[key] && data) {
                try {
                    // Create a mock request/response for each handler
                    const mockReq = { ...req, body: data, user: req.user };
                    const mockRes = {
                        status: () => ({ json: (result) => result }),
                        json: (result) => result
                    };
                    
                    const result = await new Promise((resolve) => {
                        updateHandlers[key](mockReq, mockRes, (error) => {
                            if (error) {
                                resolve({ step: key, status: 'failed', error: error.message });
                            }
                        });
                        // If no error, resolve with success
                        setTimeout(() => resolve({ step: key, status: 'success' }), 100);
                    });
                    
                    results.push(result);
                } catch (error) {
                    results.push({ step: key, status: 'failed', error: error.message });
                }
            }
        }
        
        res.status(200).json({
            status: 'success',
            message: 'Bulk update completed',
            results
        });
    } catch (error) {
        next(error);
    }
});

module.exports = router;