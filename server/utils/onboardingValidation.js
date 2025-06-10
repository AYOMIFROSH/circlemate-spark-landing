const Joi = require('joi');

// Validation schemas
const schemas = {
    communitySelection: Joi.object({
        communityId: Joi.string().hex().length(24),
        inviteCode: Joi.string().alphanum().length(8).uppercase()
    }).xor('communityId', 'inviteCode'), // One of them is required

    profileUpdate: Joi.object({
        firstName: Joi.string().min(2).max(50).required(),
        lastName: Joi.string().min(2).max(50).required(),
        age: Joi.number()
            .integer()
            .min(18)
            .max(120)
            .required()
            .messages({
                'number.min': 'You must be at least 18 years old to use CircleMate',
                'number.max': 'Please enter a valid age'
            }), 
        gender: Joi.string().valid('male', 'female').required(),
        bio: Joi.string().max(500).allow(''),
        occupation: Joi.string().max(200).allow(''),
        // NEW FIELDS
        temperament: Joi.string().valid('choleric', 'sanguine', 'phlegmatic', 'melancholic').required(),
        matchingStyle: Joi.string().valid('flexible', 'strict', 'auto').required(),
        ageRange: Joi.string().valid('18-25', '26-35', '36-45', '46+').required(),
        educationLevel: Joi.string().valid(
            'no_formal',
            'primary',
            'lower_secondary',
            'upper_secondary',
            'vocational',
            'some_college',
            'associate',
            'bachelor',
            'postgrad_diploma',
            'master',
            'doctorate'
        ).required()
    }),

    location: Joi.object({
        city: Joi.string().min(2).required(),
        state: Joi.string().min(2).required(),
        country: Joi.string().min(2).required(),
        postalCode: Joi.string().min(3).required(),
        latitude: Joi.number().min(-90).max(90).optional(),
        longitude: Joi.number().min(-180).max(180).optional()
    }),

    personality: Joi.object({
        personalityTraits: Joi.array()
            .items(Joi.string().valid(
                'adventurous', 'analytical', 'creative', 'empathetic',
                'organized', 'outgoing', 'relaxed', 'ambitious',
                'thoughtful', 'practical', 'curious', 'reliable'
            ))
            .min(1)
            .max(5)
            .required()
    }),

    preferences: Joi.object({
        connectionPurposes: Joi.array()
            .items(Joi.string().valid('friendship', 'dating', 'networking', 'activities'))
            .min(1)
            .required(),
        interests: Joi.array()
            .items(Joi.string().trim())
            .min(1)
            .required(),
        // Accept connectionAgePreferences instead of preferredAges
        connectionAgePreferences: Joi.object().pattern(
            Joi.string().valid('friendship', 'dating', 'networking', 'activities'),
            Joi.object({
                min: Joi.number().integer().min(18).max(100).required(),
                max: Joi.number().integer().min(18).max(100).required()
            }).custom((value, helpers) => {
                if (value.min > value.max) {
                    return helpers.error('any.invalid', {
                        message: 'Minimum age must be less than or equal to maximum age'
                    });
                }
                return value;
            })
        ).optional()
    }),

    availability: Joi.object({
        days: Joi.array()
            .items(Joi.string().valid(
                'Monday', 'Tuesday', 'Wednesday', 'Thursday',
                'Friday', 'Saturday', 'Sunday'
            ))
            .min(1)
            .required(),
        timePreferences: Joi.array()
            .items(Joi.string().valid('morning', 'afternoon', 'evening', 'night'))
            .min(1)
            .required()
    })
};

// Validation middleware factory
const validate = (schema) => {
    return async (req, res, next) => {
        try {
            await schema.validateAsync(req.body, { abortEarly: false });
            next();
        } catch (error) {
            const errors = error.details.map(detail => ({
                field: detail.path.join('.'),
                message: detail.message
            }));

            return res.status(400).json({
                status: 'FAILED',
                message: 'Validation failed',
                errors
            });
        }
    };
};

// Export validation middleware
module.exports = {
    validateCommunitySelection: validate(schemas.communitySelection),
    validateProfileUpdate: validate(schemas.profileUpdate),
    validateLocation: validate(schemas.location),
    validatePersonality: validate(schemas.personality),
    validatePreferences: validate(schemas.preferences),
    validateAvailability: validate(schemas.availability)
};