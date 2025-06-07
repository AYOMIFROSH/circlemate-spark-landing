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
        default: 'Unknown'
    },
    ipAddress: {
        type: String,
        default: 'Unknown'
    },
    isActive: {
        type: Boolean,
        default: true,
        index: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastAccessed: {
        type: Date,
        default: Date.now
    },
    expiresAt: {
        type: Date,
        required: true,
        index: { expireAfterSeconds: 0 } // MongoDB TTL index for automatic cleanup
    },
    loggedOutAt: {
        type: Date,
        default: null
    }
});

// Compound index for efficient queries
sessionSchema.index({ userId: 1, isActive: 1 });
sessionSchema.index({ sessionToken: 1, isActive: 1 });

// Virtual for session duration
sessionSchema.virtual('duration').get(function() {
    if (this.loggedOutAt) {
        return this.loggedOutAt - this.createdAt;
    }
    return this.lastAccessed - this.createdAt;
});

// Instance method to check if session is expired
sessionSchema.methods.isExpired = function() {
    return this.expiresAt < new Date() || !this.isActive;
};

// Static method to cleanup expired sessions
sessionSchema.statics.cleanupExpired = async function() {
    return this.deleteMany({
        $or: [
            { expiresAt: { $lt: new Date() } },
            { isActive: false, loggedOutAt: { $lt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } }
        ]
    });
};

const Session = mongoose.model('Session', sessionSchema);
module.exports = Session;