const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    userName: {
        type: String,
        required: [true, 'Username is required'],
        trim: true,
        minlength: [3, 'Username must be at least 3 characters'],
        maxlength: [30, 'Username cannot exceed 30 characters']
    },
    firstName: {
        type: String,
        required: [true, 'First name is required'],
        trim: true,
        maxlength: [50, 'First name cannot exceed 50 characters']
    },
    lastName: {
        type: String,
        required: [true, 'Last name is required'],
        trim: true,
        maxlength: [50, 'Last name cannot exceed 50 characters']
    },
    email: {
        type: String,
        unique: true,
        required: [true, 'Email is required'],
        index: true,
        lowercase: true,
        trim: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please provide a valid email']
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'Admin'], // Keep 'Admin' for backward compatibility
        default: 'user',
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [8, 'Password must be at least 8 characters']
    },
    verified: {
        type: Boolean,
        required: true,
        default: false
    },
    // Password reset fields
    resetToken: {
        type: String,
        default: null,
    },
    resetTokenExpiry: {
        type: Date,
        default: null,
    },
    lastPasswordResetRequest: {
        type: Date,
        default: null
    },
    passwordChangedAt: {
        type: Date
    },
    // Security fields
    failedLoginAttempts: {
        type: Number,
        default: 0
    },
    lastFailedLogin: {
        type: Date,
        default: null
    },
    accountLockedUntil: {
        type: Date,
        default: null
    },
    // Token fields
    refreshToken: {
        type: String,
        default: null
    },
    // Session-related fields
    lastLoginAt: {
        type: Date,
        default: null
    },
    lastLoginIp: {
        type: String,
        default: null
    },
    // Metadata
    createdAt: {
        type: Date,
        default: Date.now,
        immutable: true
    },
    updatedAt: {
        type: Date,
        default: Date.now
    },
    // Account status
    isActive: {
        type: Boolean,
        default: true
    },
    deactivatedAt: {
        type: Date,
        default: null
    }
});

// Indexes for performance
userSchema.index({ email: 1, verified: 1 });
userSchema.index({ resetToken: 1, resetTokenExpiry: 1 });
userSchema.index({ createdAt: -1 });

// Update the updatedAt field before saving
userSchema.pre('save', function(next) {
    this.updatedAt = new Date();
    
    // Normalize role to lowercase (except for backward compatibility)
    if (this.role === 'Admin') {
        // Keep 'Admin' for backward compatibility
    } else if (this.role) {
        this.role = this.role.toLowerCase();
    }
    
    next();
});

// Virtual for full name
userSchema.virtual('fullName').get(function() {
    return `${this.firstName} ${this.lastName}`;
});

// Virtual to check if account is locked
userSchema.virtual('isLocked').get(function() {
    return this.accountLockedUntil && this.accountLockedUntil > new Date();
});

// Instance method to check if user has active sessions
userSchema.methods.hasActiveSessions = async function() {
    const Session = mongoose.model('Session');
    const count = await Session.countDocuments({
        userId: this._id,
        isActive: true,
        expiresAt: { $gt: new Date() }
    });
    return count > 0;
};

// Instance method to check if password was changed after JWT was issued
userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
    if (this.passwordChangedAt) {
        const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
        return JWTTimestamp < changedTimestamp;
    }
    return false;
};

// Instance method to increment failed login attempts
userSchema.methods.incrementFailedLogins = async function() {
    this.failedLoginAttempts += 1;
    this.lastFailedLogin = new Date();
    
    // Lock account after 5 failed attempts
    if (this.failedLoginAttempts >= 5) {
        this.accountLockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
    }
    
    await this.save();
};

// Instance method to reset failed login attempts
userSchema.methods.resetFailedLogins = async function() {
    this.failedLoginAttempts = 0;
    this.lastFailedLogin = null;
    this.accountLockedUntil = null;
    await this.save();
};

// Static method to find users with active sessions
userSchema.statics.findUsersWithActiveSessions = function() {
    return this.aggregate([
        {
            $match: {
                isActive: true,
                verified: true
            }
        },
        {
            $lookup: {
                from: 'sessions',
                localField: '_id',
                foreignField: 'userId',
                as: 'sessions'
            }
        },
        {
            $match: {
                'sessions': {
                    $elemMatch: {
                        isActive: true,
                        expiresAt: { $gt: new Date() }
                    }
                }
            }
        },
        {
            $project: {
                password: 0,
                resetToken: 0,
                refreshToken: 0
            }
        }
    ]);
};

// Static method to find inactive users
userSchema.statics.findInactiveUsers = function(daysInactive = 90) {
    const cutoffDate = new Date(Date.now() - daysInactive * 24 * 60 * 60 * 1000);
    return this.find({
        lastLoginAt: { $lt: cutoffDate },
        isActive: true
    }).select('-password -resetToken -refreshToken');
};

// Static method to clean up unverified accounts older than 7 days
userSchema.statics.cleanupUnverifiedAccounts = async function() {
    const cutoffDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    return this.deleteMany({
        verified: false,
        createdAt: { $lt: cutoffDate }
    });
};

// Ensure virtuals are included in JSON
userSchema.set('toJSON', {
    virtuals: true,
    transform: function(doc, ret) {
        delete ret.password;
        delete ret.resetToken;
        delete ret.refreshToken;
        delete ret.__v;
        return ret;
    }
});

const User = mongoose.model('User', userSchema);
module.exports = User;