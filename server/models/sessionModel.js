const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
    sessionToken: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
    },
    userAgent: {
        type: String,
        default: 'Unknown',
        maxlength: 500
    },
    ipAddress: {
        type: String,
        default: 'Unknown',
        index: true // Add index for IP-based queries
    },
    deviceFingerprint: {
        type: String,
        index: true // For device-based session management
    },
    isActive: {
        type: Boolean,
        default: true,
        index: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        immutable: true
    },
    lastAccessed: {
        type: Date,
        default: Date.now,
    },
    expiresAt: {
        type: Date,
        required: true,
        index: { expireAfterSeconds: 0 } // MongoDB TTL index for automatic cleanup
    },
    loggedOutAt: {
        type: Date,
        default: null,
        index: true,
        sparse: true // Only index non-null values
    },
    // Additional security fields
    loginMethod: {
        type: String,
        enum: ['password', 'oauth', 'magic-link'],
        default: 'password'
    },
    // Geolocation data
    location: {
        country: String,
        region: String,
        city: String,
        coordinates: {
            type: [Number], // [longitude, latitude]
            index: '2dsphere'
        }
    },
    // Session metadata
    metadata: {
        type: Map,
        of: mongoose.Schema.Types.Mixed
    }
}, {
    timestamps: true,
    // Optimize queries by excluding version key
    versionKey: false,
    // Use lean queries by default for better performance
    toJSON: {
        transform: function(doc, ret) {
            delete ret._id;
            delete ret.__v;
            return ret;
        }
    }
});

// Compound indexes for efficient queries
sessionSchema.index({ userId: 1, isActive: 1, expiresAt: -1 });
sessionSchema.index({ sessionToken: 1, isActive: 1 });
sessionSchema.index({ userId: 1, deviceFingerprint: 1 });
sessionSchema.index({ createdAt: -1 });
sessionSchema.index({ lastAccessed: 1 }); // For finding stale sessions

// Virtual for session duration
sessionSchema.virtual('duration').get(function() {
    if (this.loggedOutAt) {
        return this.loggedOutAt - this.createdAt;
    }
    return this.lastAccessed - this.createdAt;
});

// Virtual for time until expiry
sessionSchema.virtual('timeUntilExpiry').get(function() {
    return Math.max(0, this.expiresAt - new Date());
});

// Instance method to check if session is expired
sessionSchema.methods.isExpired = function() {
    return this.expiresAt < new Date() || !this.isActive;
};

// Instance method to extend session
sessionSchema.methods.extend = async function(duration = 24 * 60 * 60 * 1000) {
    this.expiresAt = new Date(Date.now() + duration);
    this.lastAccessed = new Date();
    return this.save();
};

// Instance method to invalidate session
sessionSchema.methods.invalidate = async function() {
    this.isActive = false;
    this.loggedOutAt = new Date();
    return this.save();
};

// Static method to cleanup expired sessions with batching
sessionSchema.statics.cleanupExpired = async function() {
    const batchSize = 1000;
    let totalDeleted = 0;
    let hasMore = true;
    
    while (hasMore) {
        const expiredSessions = await this.find({
            $or: [
                { expiresAt: { $lt: new Date() } },
                { 
                    isActive: false, 
                    loggedOutAt: { $lt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } 
                }
            ]
        })
        .select('_id')
        .limit(batchSize)
        .lean();
        
        if (expiredSessions.length === 0) {
            hasMore = false;
        } else {
            const ids = expiredSessions.map(s => s._id);
            const result = await this.deleteMany({ _id: { $in: ids } });
            totalDeleted += result.deletedCount;
            
            // Add small delay to prevent overwhelming the database
            await new Promise(resolve => setTimeout(resolve, 100));
        }
    }
    
    return { deletedCount: totalDeleted };
};

// Static method to find active sessions for a user
sessionSchema.statics.findActiveSessions = function(userId, options = {}) {
    const query = {
        userId,
        isActive: true,
        expiresAt: { $gt: new Date() }
    };
    
    return this.find(query)
        .select(options.select || '-metadata')
        .sort(options.sort || '-lastAccessed')
        .limit(options.limit || 10)
        .lean();
};

// Static method to invalidate all sessions for a user
sessionSchema.statics.invalidateUserSessions = async function(userId, exceptSessionToken = null) {
    const query = {
        userId,
        isActive: true
    };
    
    if (exceptSessionToken) {
        query.sessionToken = { $ne: exceptSessionToken };
    }
    
    return this.updateMany(query, {
        isActive: false,
        loggedOutAt: new Date()
    });
};

// Static method to get session statistics
sessionSchema.statics.getSessionStats = async function(userId = null) {
    const matchStage = userId ? { userId: mongoose.Types.ObjectId(userId) } : {};
    
    const stats = await this.aggregate([
        { $match: matchStage },
        {
            $facet: {
                total: [
                    { $count: 'count' }
                ],
                active: [
                    {
                        $match: {
                            isActive: true,
                            expiresAt: { $gt: new Date() }
                        }
                    },
                    { $count: 'count' }
                ],
                byDevice: [
                    {
                        $match: {
                            isActive: true,
                            expiresAt: { $gt: new Date() }
                        }
                    },
                    {
                        $group: {
                            _id: '$userAgent',
                            count: { $sum: 1 }
                        }
                    },
                    { $sort: { count: -1 } },
                    { $limit: 10 }
                ],
                byLocation: [
                    {
                        $match: {
                            isActive: true,
                            expiresAt: { $gt: new Date() },
                            'location.country': { $exists: true }
                        }
                    },
                    {
                        $group: {
                            _id: '$location.country',
                            count: { $sum: 1 }
                        }
                    },
                    { $sort: { count: -1 } },
                    { $limit: 10 }
                ],
                avgDuration: [
                    {
                        $match: {
                            loggedOutAt: { $exists: true }
                        }
                    },
                    {
                        $project: {
                            duration: {
                                $subtract: ['$loggedOutAt', '$createdAt']
                            }
                        }
                    },
                    {
                        $group: {
                            _id: null,
                            avgDuration: { $avg: '$duration' }
                        }
                    }
                ]
            }
        }
    ]);
    
    return {
        total: stats[0].total[0]?.count || 0,
        active: stats[0].active[0]?.count || 0,
        byDevice: stats[0].byDevice,
        byLocation: stats[0].byLocation,
        avgDurationMs: stats[0].avgDuration[0]?.avgDuration || 0
    };
};

// Static method to detect suspicious sessions
sessionSchema.statics.detectSuspiciousSessions = async function(userId) {
    const userSessions = await this.find({
        userId,
        isActive: true,
        expiresAt: { $gt: new Date() }
    }).lean();
    
    const suspicious = [];
    const locations = new Map();
    const devices = new Map();
    
    for (const session of userSessions) {
        // Check for multiple locations
        if (session.location?.country) {
            const key = `${session.location.country}-${session.location.city}`;
            locations.set(key, (locations.get(key) || 0) + 1);
        }
        
        // Check for multiple devices
        if (session.deviceFingerprint) {
            devices.set(session.deviceFingerprint, (devices.get(session.deviceFingerprint) || 0) + 1);
        }
        
        // Check for rapid session creation
        const recentSessions = userSessions.filter(s => 
            Math.abs(s.createdAt - session.createdAt) < 60000 && // Within 1 minute
            s._id.toString() !== session._id.toString()
        );
        
        if (recentSessions.length > 2) {
            suspicious.push({
                sessionId: session._id,
                reason: 'Rapid session creation',
                details: `${recentSessions.length + 1} sessions created within 1 minute`
            });
        }
    }
    
    // Flag if user has sessions from multiple countries
    if (locations.size > 2) {
        suspicious.push({
            reason: 'Multiple locations',
            details: `Active sessions from ${locations.size} different locations`
        });
    }
    
    // Flag if too many active sessions
    if (userSessions.length > 10) {
        suspicious.push({
            reason: 'Too many active sessions',
            details: `${userSessions.length} active sessions`
        });
    }
    
    return suspicious;
};

// Static method for efficient session count
sessionSchema.statics.countActiveSessions = async function(userId = null) {
    const query = {
        isActive: true,
        expiresAt: { $gt: new Date() }
    };
    
    if (userId) {
        query.userId = userId;
    }
    
    return this.countDocuments(query);
};

// Pre-save middleware to set deviceFingerprint
sessionSchema.pre('save', function(next) {
    if (this.isNew && !this.deviceFingerprint && this.userAgent && this.ipAddress) {
        const crypto = require('crypto');
        this.deviceFingerprint = crypto
            .createHash('md5')
            .update(this.userAgent + this.ipAddress)
            .digest('hex');
    }
    next();
});

// Post-save middleware to clear cache
sessionSchema.post('save', async function(doc) {
    try {
        const redis = require('../utils/redis');
        await redis.del(`session:${doc.sessionToken}`);
    } catch (error) {
        console.error('Failed to clear session cache:', error);
    }
});

// Post-remove middleware to clear cache
sessionSchema.post('remove', async function(doc) {
    try {
        const redis = require('../utils/redis');
        await redis.del(`session:${doc.sessionToken}`);
    } catch (error) {
        console.error('Failed to clear session cache:', error);
    }
});

// Ensure virtuals are included in JSON output
sessionSchema.set('toJSON', {
    virtuals: true,
    transform: function(doc, ret) {
        delete ret._id;
        delete ret.id;
        return ret;
    }
});

const Session = mongoose.model('Session', sessionSchema);
module.exports = Session;