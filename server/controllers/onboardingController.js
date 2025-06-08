const UserProfile = require('../models/userProfileModel');
const Community = require('../models/communityModel');
const User = require('../models/userModel');
const createError = require('../utils/appError');
const logger = require('../utils/logger');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const mongoose = require('mongoose');
const DOMPurify = require('isomorphic-dompurify');

// Validate Cloudinary configuration
const validateCloudinaryConfig = () => {
    const required = ['CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET'];
    const missing = required.filter(key => !process.env[key]);
    
    if (missing.length > 0) {
        logger.warn(`Missing Cloudinary configuration: ${missing.join(', ')}`);
        return false;
    }
    return true;
};

// Configure Cloudinary if credentials exist
let cloudinaryConfigured = false;
if (validateCloudinaryConfig()) {
    try {
        cloudinary.config({
            cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
            api_key: process.env.CLOUDINARY_API_KEY,
            api_secret: process.env.CLOUDINARY_API_SECRET
        });
        cloudinaryConfigured = true;
        logger.info('Cloudinary configured successfully');
    } catch (error) {
        logger.error('Cloudinary configuration error:', error);
    }
} else {
    logger.warn('Cloudinary not configured - photo uploads will be disabled');
}

// Multer configuration for file uploads
const storage = multer.memoryStorage();
const upload = multer({
    storage,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB limit
        files: 8 // Max 8 files
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'), false);
        }
    }
});

// Helper function to get or create user profile - INDEPENDENT VERSION
const getOrCreateProfile = async (userId, session = null) => {
    try {
        let profile = await UserProfile.findOne({ userId }).session(session);
        
        if (!profile) {
            // Create minimal profile without requiring any fields
            profile = new UserProfile({ 
                userId,
                // Set defaults to ensure other routes can work
                onboardingStep: 0,
                communities: [],
                personalityTraits: [],
                connectionPurposes: [],
                interests: [],
                profilePhotos: []
            });
            await profile.save({ session });
            logger.info(`Created new profile for user: ${userId}`);
        }
        
        return profile;
    } catch (error) {
        logger.error('Error in getOrCreateProfile:', error);
        throw error;
    }
};

// 1. Community Selection - INDEPENDENT
exports.selectCommunity = async (req, res, next) => {
    const session = await mongoose.startSession();
    
    try {
        session.startTransaction();
        
        const { communityId, inviteCode } = req.body;
        const userId = req.user._id;

        logger.info(`User ${userId} selecting community`);

        let community;

        // Join by invite code
        if (inviteCode) {
            community = await Community.findOne({ 
                inviteCode: inviteCode.toUpperCase(),
                isActive: true 
            }).session(session);
            
            if (!community) {
                await session.abortTransaction();
                return next(new createError('Invalid invite code', 400));
            }
        } 
        // Join by community ID
        else if (communityId) {
            community = await Community.findById(communityId).session(session);
            
            if (!community || !community.isActive) {
                await session.abortTransaction();
                return next(new createError('Community not found or inactive', 404));
            }
        } else {
            await session.abortTransaction();
            return next(new createError('Please provide either communityId or inviteCode', 400));
        }

        // Get or create user profile - won't fail if profile is incomplete
        const profile = await getOrCreateProfile(userId, session);

        // Check if already a member
        const isMember = profile.communities.some(
            c => c.communityId.toString() === community._id.toString()
        );

        if (isMember) {
            await session.abortTransaction();
            return next(new createError('You are already a member of this community', 400));
        }

        // Add user to community
        profile.communities.push({
            communityId: community._id,
            joinedAt: new Date(),
            role: 'member'
        });
        
        // Add user to community members list
        if (!community.members.includes(userId)) {
            community.members.push(userId);
            community.memberCount = community.members.length;
            await community.save({ session });
        }

        // Update onboarding step only if it's less than 1
        if (profile.onboardingStep < 1) {
            profile.onboardingStep = 1;
        }
        
        await profile.save({ session });

        // Commit transaction
        await session.commitTransaction();

        res.status(200).json({
            status: 'success',
            message: 'Successfully joined community',
            data: {
                community: {
                    _id: community._id,
                    name: community.name,
                    memberCount: community.memberCount
                },
                onboardingStep: profile.onboardingStep
            }
        });
    } catch (error) {
        await session.abortTransaction();
        logger.error('Community selection error:', error);
        next(error);
    } finally {
        session.endSession();
    }
};

// 2. Profile Information - INDEPENDENT
exports.updateProfile = async (req, res, next) => {
    const session = await mongoose.startSession();
    
    try {
        session.startTransaction();
        
        const userId = req.user._id;
        const { 
            firstName, 
            lastName, 
            age, 
            gender, 
            bio, 
            occupation,
            temperament,
            matchingStyle,
            ageRange,
            educationLevel
        } = req.body;

        // Validation for this specific route only
        if (!firstName || !lastName || !age || !gender || !temperament || 
            !matchingStyle || !ageRange || !educationLevel) {
            await session.abortTransaction();
            return next(new createError('All required fields must be provided', 400));
        }

        // Get or create profile - won't fail if incomplete
        const profile = await getOrCreateProfile(userId, session);

        // Sanitize and update only the fields for this route
        profile.firstName = DOMPurify.sanitize(firstName);
        profile.lastName = DOMPurify.sanitize(lastName);
        profile.age = parseInt(age);
        profile.gender = gender;
        profile.bio = DOMPurify.sanitize(bio || '');
        profile.occupation = DOMPurify.sanitize(occupation || '');
        profile.temperament = temperament;
        profile.matchingStyle = matchingStyle;
        profile.ageRange = ageRange;
        profile.educationLevel = educationLevel;

        // Update onboarding step only if needed
        if (profile.onboardingStep < 2) {
            profile.onboardingStep = 2;
        }
        
        await profile.save({ session });

        // Also update the main User model
        await User.findByIdAndUpdate(
            userId, 
            {
                firstName: profile.firstName,
                lastName: profile.lastName
            },
            { session }
        );

        await session.commitTransaction();

        res.status(200).json({
            status: 'success',
            message: 'Profile updated successfully',
            data: {
                profile: {
                    firstName: profile.firstName,
                    lastName: profile.lastName,
                    age: profile.age,
                    gender: profile.gender,
                    bio: profile.bio,
                    occupation: profile.occupation,
                    temperament: profile.temperament,
                    matchingStyle: profile.matchingStyle,
                    ageRange: profile.ageRange,
                    educationLevel: profile.educationLevel
                },
                onboardingStep: profile.onboardingStep
            }
        });
    } catch (error) {
        await session.abortTransaction();
        logger.error('Profile update error:', error);
        next(error);
    } finally {
        session.endSession();
    }
};

// 3. Location Information - INDEPENDENT
exports.updateLocation = async (req, res, next) => {
    try {
        const userId = req.user._id;
        const { city, state, country, postalCode, latitude, longitude } = req.body;

        // Validation for this route only
        if (!city || !state || !country || !postalCode) {
            return next(new createError('All location fields are required', 400));
        }

        // Get or create profile
        const profile = await getOrCreateProfile(userId);

        // Sanitize and update location only
        profile.location = {
            city: DOMPurify.sanitize(city),
            state: DOMPurify.sanitize(state),
            country: DOMPurify.sanitize(country),
            postalCode: DOMPurify.sanitize(postalCode),
            coordinates: {
                latitude: latitude ? parseFloat(latitude) : null,
                longitude: longitude ? parseFloat(longitude) : null
            }
        };

        // Update onboarding step only if needed
        if (profile.onboardingStep < 3) {
            profile.onboardingStep = 3;
        }
        
        await profile.save();

        res.status(200).json({
            status: 'success',
            message: 'Location updated successfully',
            data: {
                location: profile.location,
                onboardingStep: profile.onboardingStep
            }
        });
    } catch (error) {
        logger.error('Location update error:', error);
        next(error);
    }
};

// 4. Personality Traits - INDEPENDENT
exports.updatePersonality = async (req, res, next) => {
    try {
        const userId = req.user._id;
        const { personalityTraits } = req.body;

        // Validation for this route only
        if (!personalityTraits || !Array.isArray(personalityTraits) || personalityTraits.length === 0) {
            return next(new createError('Please select at least one personality trait', 400));
        }

        if (personalityTraits.length > 5) {
            return next(new createError('You can select up to 5 personality traits', 400));
        }

        // Get or create profile
        const profile = await getOrCreateProfile(userId);

        // Update personality traits only
        profile.personalityTraits = personalityTraits;

        // Update onboarding step only if needed
        if (profile.onboardingStep < 4) {
            profile.onboardingStep = 4;
        }
        
        await profile.save();

        res.status(200).json({
            status: 'success',
            message: 'Personality traits updated successfully',
            data: {
                personalityTraits: profile.personalityTraits,
                onboardingStep: profile.onboardingStep
            }
        });
    } catch (error) {
        logger.error('Personality update error:', error);
        next(error);
    }
};

// 5. Connection Preferences - INDEPENDENT
exports.updatePreferences = async (req, res, next) => {
    try {
        const userId = req.user._id;
        const { connectionPurposes, interests, preferredAges } = req.body;

        // Validation for this route only
        if (!connectionPurposes || !Array.isArray(connectionPurposes) || connectionPurposes.length === 0) {
            return next(new createError('Please select at least one connection purpose', 400));
        }

        if (!interests || !Array.isArray(interests) || interests.length === 0) {
            return next(new createError('Please select at least one interest', 400));
        }

        // Get or create profile
        const profile = await getOrCreateProfile(userId);

        // Update preferences only
        profile.connectionPurposes = connectionPurposes;
        profile.interests = interests.map(interest => DOMPurify.sanitize(interest));
        
        // Update age preferences if provided
        if (preferredAges && typeof preferredAges === 'object') {
            profile.connectionAgePreferences = new Map();
            
            for (const [purpose, ageRange] of Object.entries(preferredAges)) {
                if (connectionPurposes.includes(purpose) && ageRange.min && ageRange.max) {
                    profile.connectionAgePreferences.set(purpose, {
                        min: parseInt(ageRange.min),
                        max: parseInt(ageRange.max)
                    });
                }
            }
        }

        // Update onboarding step only if needed
        if (profile.onboardingStep < 5) {
            profile.onboardingStep = 5;
        }
        
        await profile.save();

        res.status(200).json({
            status: 'success',
            message: 'Preferences updated successfully',
            data: {
                connectionPurposes: profile.connectionPurposes,
                interests: profile.interests,
                connectionAgePreferences: Object.fromEntries(profile.connectionAgePreferences || new Map()),
                onboardingStep: profile.onboardingStep
            }
        });
    } catch (error) {
        logger.error('Preferences update error:', error);
        next(error);
    }
};

// 6. Availability - INDEPENDENT
exports.updateAvailability = async (req, res, next) => {
    try {
        const userId = req.user._id;
        const { days, timePreferences } = req.body;

        // Validation for this route only
        if (!days || !Array.isArray(days) || days.length === 0) {
            return next(new createError('Please select at least one day', 400));
        }

        if (!timePreferences || !Array.isArray(timePreferences) || timePreferences.length === 0) {
            return next(new createError('Please select at least one time preference', 400));
        }

        // Get or create profile
        const profile = await getOrCreateProfile(userId);

        // Update availability only
        profile.availability = {
            days,
            timePreferences
        };

        // Update onboarding step only if needed
        if (profile.onboardingStep < 6) {
            profile.onboardingStep = 6;
        }
        
        await profile.save();

        res.status(200).json({
            status: 'success',
            message: 'Availability updated successfully',
            data: {
                availability: profile.availability,
                onboardingStep: profile.onboardingStep
            }
        });
    } catch (error) {
        logger.error('Availability update error:', error);
        next(error);
    }
};

// 7. Profile Photos Upload - INDEPENDENT
exports.uploadPhotos = [
    upload.array('photos', 8),
    async (req, res, next) => {
        try {
            // Check if Cloudinary is configured
            if (!cloudinaryConfigured) {
                return res.status(200).json({
                    status: 'success',
                    message: 'Photo upload service is currently unavailable, but your profile is saved',
                    data: {
                        photos: [],
                        onboardingStep: 7,
                        onboardingCompleted: true,
                        skipPhotos: true
                    }
                });
            }

            const userId = req.user._id;
            const files = req.files;

            // Allow skipping photos
            if (!files || files.length === 0) {
                // Get profile and mark as complete anyway
                const profile = await getOrCreateProfile(userId);
                
                if (profile.onboardingStep < 7) {
                    profile.onboardingStep = 7;
                }
                
                // Can complete onboarding without photos
                profile.onboardingCompleted = true;
                profile.onboardingCompletedAt = new Date();
                await profile.save();

                return res.status(200).json({
                    status: 'success',
                    message: 'Profile completed without photos',
                    data: {
                        photos: profile.profilePhotos,
                        onboardingStep: profile.onboardingStep,
                        onboardingCompleted: profile.onboardingCompleted
                    }
                });
            }

            // Get or create profile
            const profile = await getOrCreateProfile(userId);

            // Upload to Cloudinary with error handling
            const uploadPromises = files.map(async (file, index) => {
                try {
                    const b64 = Buffer.from(file.buffer).toString('base64');
                    const dataURI = `data:${file.mimetype};base64,${b64}`;
                    
                    const result = await cloudinary.uploader.upload(dataURI, {
                        folder: `user_profiles/${userId}`,
                        resource_type: 'auto',
                        transformation: [
                            { width: 800, height: 800, crop: 'limit' },
                            { quality: 'auto' }
                        ]
                    });

                    return {
                        url: result.secure_url,
                        publicId: result.public_id,
                        isPrimary: index === 0 && profile.profilePhotos.length === 0
                    };
                } catch (uploadError) {
                    logger.error(`Failed to upload photo ${index}:`, uploadError);
                    throw new Error(`Failed to upload photo ${index + 1}`);
                }
            });

            try {
                const uploadedPhotos = await Promise.all(uploadPromises);
                
                // Add photos to profile
                profile.profilePhotos.push(...uploadedPhotos);

                // Update onboarding step
                if (profile.onboardingStep < 7) {
                    profile.onboardingStep = 7;
                }
                
                profile.onboardingCompleted = true;
                profile.onboardingCompletedAt = new Date();
                
                await profile.save();

                res.status(200).json({
                    status: 'success',
                    message: 'Photos uploaded successfully',
                    data: {
                        photos: profile.profilePhotos,
                        onboardingStep: profile.onboardingStep,
                        onboardingCompleted: profile.onboardingCompleted
                    }
                });
            } catch (uploadError) {
                // If upload fails, still allow profile completion
                logger.error('Photo upload failed, completing profile without photos:', uploadError);
                
                if (profile.onboardingStep < 7) {
                    profile.onboardingStep = 7;
                }
                
                profile.onboardingCompleted = true;
                profile.onboardingCompletedAt = new Date();
                await profile.save();

                res.status(200).json({
                    status: 'success',
                    message: 'Profile completed, but some photos failed to upload',
                    data: {
                        photos: profile.profilePhotos,
                        onboardingStep: profile.onboardingStep,
                        onboardingCompleted: profile.onboardingCompleted,
                        photoErrors: true
                    }
                });
            }
        } catch (error) {
            logger.error('Photo upload error:', error);
            next(error);
        }
    }
];

// Delete a photo - INDEPENDENT
exports.deletePhoto = async (req, res, next) => {
    try {
        const userId = req.user._id;
        const { photoId } = req.params;

        const profile = await UserProfile.findOne({ userId });
        
        if (!profile) {
            return next(new createError('Profile not found', 404));
        }

        const photo = profile.profilePhotos.id(photoId);
        
        if (!photo) {
            return next(new createError('Photo not found', 404));
        }

        // Delete from Cloudinary if configured
        if (photo.publicId && cloudinaryConfigured) {
            try {
                await cloudinary.uploader.destroy(photo.publicId);
            } catch (error) {
                logger.error('Failed to delete photo from Cloudinary:', error);
                // Continue with deletion even if Cloudinary fails
            }
        }

        // Remove from profile
        profile.profilePhotos.pull(photoId);
        await profile.save();

        res.status(200).json({
            status: 'success',
            message: 'Photo deleted successfully'
        });
    } catch (error) {
        logger.error('Photo deletion error:', error);
        next(error);
    }
};

// Get onboarding status - ALWAYS WORKS
exports.getOnboardingStatus = async (req, res, next) => {
    try {
        const userId = req.user._id;
        const profile = await UserProfile.findOne({ userId })
            .populate('communities.communityId', 'name memberCount')
            .lean();

        // Return default status if no profile exists
        if (!profile) {
            return res.status(200).json({
                status: 'success',
                data: {
                    onboardingStep: 0,
                    onboardingCompleted: false,
                    profileCompleteness: 0,
                    profile: null
                }
            });
        }

        // Calculate actual completeness based on what's filled
        let completeness = 0;
        if (profile.communities && profile.communities.length > 0) completeness += 14;
        if (profile.firstName && profile.lastName && profile.age) completeness += 14;
        if (profile.location && profile.location.city) completeness += 14;
        if (profile.personalityTraits && profile.personalityTraits.length > 0) completeness += 14;
        if (profile.connectionPurposes && profile.connectionPurposes.length > 0) completeness += 14;
        if (profile.availability && profile.availability.days && profile.availability.days.length > 0) completeness += 15;
        if (profile.profilePhotos && profile.profilePhotos.length > 0) completeness += 15;

        res.status(200).json({
            status: 'success',
            data: {
                onboardingStep: profile.onboardingStep || 0,
                onboardingCompleted: profile.onboardingCompleted || false,
                profileCompleteness: completeness,
                profile: profile
            }
        });
    } catch (error) {
        logger.error('Get onboarding status error:', error);
        // Return default response even on error
        res.status(200).json({
            status: 'success',
            data: {
                onboardingStep: 0,
                onboardingCompleted: false,
                profileCompleteness: 0,
                profile: null
            }
        });
    }
};

// Get available communities - INDEPENDENT
exports.getCommunities = async (req, res, next) => {
    try {
        const { search, page = 1, limit = 20 } = req.query;
        
        let query = { isActive: true };
        
        if (search) {
            query.name = { $regex: search, $options: 'i' };
        }

        const skip = (parseInt(page) - 1) * parseInt(limit);

        const [communities, total] = await Promise.all([
            Community.find(query)
                .select('name description memberCount inviteCode')
                .sort({ memberCount: -1 })
                .skip(skip)
                .limit(parseInt(limit))
                .lean(),
            Community.countDocuments(query)
        ]);

        res.status(200).json({
            status: 'success',
            data: {
                communities,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / parseInt(limit))
                }
            }
        });
    } catch (error) {
        logger.error('Get communities error:', error);
        // Return empty list on error
        res.status(200).json({
            status: 'success',
            data: {
                communities: [],
                pagination: {
                    page: 1,
                    limit: 20,
                    total: 0,
                    pages: 0
                }
            }
        });
    }
};

// Complete onboarding - FLEXIBLE
exports.completeOnboarding = async (req, res, next) => {
    const session = await mongoose.startSession();
    
    try {
        session.startTransaction();
        
        const userId = req.user._id;
        const { forceComplete = false } = req.body; // Allow force completion
        
        const profile = await UserProfile.findOne({ userId }).session(session);

        if (!profile) {
            await session.abortTransaction();
            return next(new createError('Profile not found', 404));
        }

        // Allow completion with minimum requirements or force completion
        const minimumStep = forceComplete ? 0 : 2; // At least basic profile info
        
        if (profile.onboardingStep < minimumStep && !forceComplete) {
            await session.abortTransaction();
            return next(new createError('Please complete at least your basic profile information', 400));
        }

        profile.onboardingCompleted = true;
        profile.onboardingCompletedAt = new Date();
        await profile.save({ session });

        // Update user's main record
        await User.findByIdAndUpdate(
            userId,
            { onboardingCompleted: true },
            { session }
        );

        await session.commitTransaction();

        res.status(200).json({
            status: 'success',
            message: 'Onboarding completed successfully',
            data: {
                onboardingCompleted: true,
                profileCompleteness: profile.profileCompleteness || 0,
                onboardingStep: profile.onboardingStep
            }
        });
    } catch (error) {
        await session.abortTransaction();
        logger.error('Complete onboarding error:', error);
        next(error);
    } finally {
        session.endSession();
    }
};