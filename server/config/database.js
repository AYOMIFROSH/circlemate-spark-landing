const mongoose = require('mongoose');
const logger = require('../utils/logger');

// Optimized MongoDB connection options for production
const mongoOptions = {
    // Connection Pool Settings - Optimized for production
    maxPoolSize: process.env.NODE_ENV === 'production' 
        ? parseInt(process.env.DB_POOL_SIZE) || 100 
        : 20,
    minPoolSize: process.env.NODE_ENV === 'production' ? 10 : 5,
    maxConnecting: 10,
    maxIdleTimeMS: 30000,
    waitQueueTimeoutMS: 5000,
    
    // Socket Settings
    socketTimeoutMS: 45000,
    connectTimeoutMS: 30000,
    serverSelectionTimeoutMS: 30000,
    heartbeatFrequencyMS: 10000,
    
    // Retry Settings
    retryWrites: true,
    retryReads: true,
    
    // Read Preference for better performance
    readPreference: 'primaryPreferred',
    readConcern: { level: 'majority' },
    
    // Write Concern
    w: 'majority',
    journal: true,
    wtimeoutMS: 2500,
    
    // Compression and optimization
    compressors: ['zlib', 'snappy'],
    zlibCompressionLevel: 6,
    
    // Monitoring
    monitorCommands: process.env.NODE_ENV === 'development',
    
    // Connection String Options
    authSource: 'admin',
    directConnection: false,
    appName: 'CircleMate',
    
    // Additional performance options
    bufferCommands: false,
    autoIndex: process.env.NODE_ENV === 'development',
    autoCreate: process.env.NODE_ENV === 'development',
};

// Connection metrics tracking
const connectionMetrics = {
    connectionAttempts: 0,
    successfulConnections: 0,
    failedConnections: 0,
    lastConnectionTime: null,
    poolStats: {
        size: 0,
        available: 0,
        pending: 0
    }
};

// Enhanced connection event handlers
const setupConnectionHandlers = (connection) => {
    connection.on('connected', () => {
        connectionMetrics.successfulConnections++;
        connectionMetrics.lastConnectionTime = new Date();
        
        logger.info('MongoDB connected successfully', {
            database: connection.name,
            host: connection.host,
            port: connection.port,
            poolSize: mongoOptions.maxPoolSize
        });
    });

    connection.on('error', (error) => {
        connectionMetrics.failedConnections++;
        logger.error('MongoDB connection error:', error);
        
        // Emit metrics for monitoring
        if (process.env.MONITORING_ENABLED === 'true') {
            // Send to monitoring service
        }
    });

    connection.on('disconnected', () => {
        logger.warn('MongoDB disconnected');
    });

    connection.on('reconnected', () => {
        logger.info('MongoDB reconnected');
    });

    connection.on('close', () => {
        logger.info('MongoDB connection closed');
    });
    
    // Monitor connection pool
    connection.on('connectionPoolCreated', (event) => {
        logger.info('Connection pool created:', event);
    });
    
    connection.on('connectionPoolClosed', (event) => {
        logger.info('Connection pool closed:', event);
    });
};

// Performance monitoring with optimization
const monitorPerformance = () => {
    let isMonitoring = false;
    
    const monitor = async () => {
        if (isMonitoring) return; // Prevent overlapping monitors
        isMonitoring = true;
        
        try {
            const admin = mongoose.connection.db.admin();
            const [serverStatus, dbStats] = await Promise.all([
                admin.serverStatus(),
                mongoose.connection.db.stats()
            ]);
            
            const metrics = {
                connections: {
                    current: serverStatus.connections.current,
                    available: serverStatus.connections.available,
                    active: serverStatus.connections.active
                },
                operations: {
                    insert: serverStatus.opcounters.insert,
                    query: serverStatus.opcounters.query,
                    update: serverStatus.opcounters.update,
                    delete: serverStatus.opcounters.delete
                },
                memory: {
                    resident: serverStatus.mem.resident,
                    virtual: serverStatus.mem.virtual
                },
                database: {
                    collections: dbStats.collections,
                    dataSize: dbStats.dataSize,
                    indexSize: dbStats.indexSize,
                    storageSize: dbStats.storageSize
                },
                uptime: serverStatus.uptime
            };
            
            // Update connection metrics
            connectionMetrics.poolStats = getPoolStats();
            
            logger.debug('MongoDB metrics:', metrics);
            
            // Alert on concerning metrics
            if (metrics.connections.current > mongoOptions.maxPoolSize * 0.8) {
                logger.warn(`High MongoDB connection usage: ${metrics.connections.current}/${mongoOptions.maxPoolSize}`);
            }
            
            if (serverStatus.globalLock && serverStatus.globalLock.ratio > 0.05) {
                logger.warn(`High MongoDB lock ratio: ${serverStatus.globalLock.ratio}`);
            }
        } catch (error) {
            logger.error('Error fetching MongoDB metrics:', error);
        } finally {
            isMonitoring = false;
        }
    };
    
    // Run monitoring every minute
    setInterval(monitor, 60000);
    
    // Run initial monitoring after 5 seconds
    setTimeout(monitor, 5000);
};

// Optimized index creation with progress tracking
const ensureIndexes = async () => {
    const indexOperations = [
        // User indexes
        {
            collection: 'users',
            indexes: [
                { key: { email: 1 }, unique: true, background: true },
                { key: { email: 1, verified: 1 }, background: true },
                { key: { email: 1, password: 1 }, background: true },
                { key: { resetToken: 1, resetTokenExpiry: 1 }, background: true, sparse: true },
                { key: { createdAt: -1 }, background: true },
                { key: { role: 1, isActive: 1, createdAt: -1 }, background: true },
                { key: { lastLoginAt: -1 }, background: true, sparse: true }
            ]
        },
        // Session indexes
        {
            collection: 'sessions',
            indexes: [
                { key: { sessionToken: 1 }, unique: true, background: true },
                { key: { userId: 1, isActive: 1, expiresAt: -1 }, background: true },
                { key: { expiresAt: 1 }, expireAfterSeconds: 0, background: true },
                { key: { userId: 1, deviceFingerprint: 1 }, background: true },
                { key: { ipAddress: 1, createdAt: -1 }, background: true },
                { key: { lastAccessed: 1 }, background: true, sparse: true }
            ]
        },
        // UserProfile indexes
        {
            collection: 'userprofiles',
            indexes: [
                { key: { userId: 1 }, unique: true, background: true },
                { key: { 'location.coordinates': '2dsphere' }, background: true },
                { key: { 'communities.communityId': 1 }, background: true },
                { key: { onboardingCompleted: 1, createdAt: -1 }, background: true },
                { key: { temperament: 1, matchingStyle: 1 }, background: true },
                { key: { age: 1, gender: 1 }, background: true },
                { key: { interests: 1 }, background: true }
            ]
        },
        // Community indexes
        {
            collection: 'communities',
            indexes: [
                { key: { name: 1 }, unique: true, background: true },
                { key: { inviteCode: 1 }, unique: true, sparse: true, background: true },
                { key: { isActive: 1, memberCount: -1 }, background: true },
                { key: { createdAt: -1 }, background: true }
            ]
        },
        // Waitlist indexes
        {
            collection: 'waitlists',
            indexes: [
                { key: { email: 1 }, unique: true, background: true },
                { key: { createdAt: -1 }, background: true },
                { key: { status: 1, createdAt: -1 }, background: true },
                { key: { interest: 1 }, background: true }
            ]
        },
        // UserVerification indexes
        {
            collection: 'userverifications',
            indexes: [
                { key: { userId: 1 }, unique: true, background: true },
                { key: { expiresAt: 1 }, expireAfterSeconds: 0, background: true },
                { key: { createdAt: -1 }, background: true }
            ]
        }
    ];
    
    logger.info('Starting database index creation...');
    const startTime = Date.now();
    let createdCount = 0;
    
    for (const operation of indexOperations) {
        try {
            const collection = mongoose.connection.collection(operation.collection);
            
            // Get existing indexes
            const existingIndexes = await collection.listIndexes().toArray();
            const existingKeys = existingIndexes.map(idx => Object.keys(idx.key).join('_'));
            
            for (const indexSpec of operation.indexes) {
                const indexKey = Object.keys(indexSpec.key).join('_');
                
                // Skip if index already exists
                if (existingKeys.includes(indexKey)) {
                    continue;
                }
                
                await collection.createIndex(indexSpec.key, {
                    ...indexSpec,
                    key: undefined // Remove key from options
                });
                
                createdCount++;
                logger.info(`Created index on ${operation.collection}: ${indexKey}`);
            }
        } catch (error) {
            logger.error(`Error creating indexes for ${operation.collection}:`, error);
        }
    }
    
    const duration = Date.now() - startTime;
    logger.info(`Database indexing completed in ${duration}ms. Created ${createdCount} new indexes.`);
};

// Connection pooling statistics
const getPoolStats = () => {
    try {
        const client = mongoose.connection.getClient();
        const topology = client.topology;
        
        if (topology && topology.s && topology.s.servers) {
            let totalConnections = 0;
            let availableConnections = 0;
            let pendingConnections = 0;
            
            topology.s.servers.forEach((server) => {
                if (server.pool) {
                    totalConnections += server.pool.totalConnectionCount;
                    availableConnections += server.pool.availableConnectionCount;
                    pendingConnections += server.pool.pendingConnectionCount;
                }
            });
            
            return {
                size: totalConnections,
                available: availableConnections,
                pending: pendingConnections,
                utilization: totalConnections > 0 
                    ? ((totalConnections - availableConnections) / totalConnections * 100).toFixed(2) + '%'
                    : '0%'
            };
        }
    } catch (error) {
        logger.error('Error getting pool stats:', error);
    }
    
    return {
        size: 0,
        available: 0,
        pending: 0,
        utilization: '0%'
    };
};

// Health check function
const checkDatabaseHealth = async () => {
    try {
        const startTime = Date.now();
        await mongoose.connection.db.admin().ping();
        const responseTime = Date.now() - startTime;
        
        const poolStats = getPoolStats();
        const isHealthy = responseTime < 1000 && poolStats.pending === 0;
        
        return {
            status: isHealthy ? 'healthy' : 'degraded',
            responseTime,
            poolStats,
            connectionMetrics
        };
    } catch (error) {
        logger.error('Database health check failed:', error);
        return {
            status: 'unhealthy',
            error: error.message,
            connectionMetrics
        };
    }
};

// Enhanced connection function with retry logic
const connectDB = async (retries = 3) => {
    connectionMetrics.connectionAttempts++;
    
    try {
        const dbUri = process.env.DB_ALT_HOST || process.env.MONGODB_URI;
        
        if (!dbUri) {
            throw new Error('MongoDB connection string not provided');
        }
        
        // Set mongoose options
        mongoose.set('strictQuery', true);
        
        // Connect to MongoDB
        await mongoose.connect(dbUri, mongoOptions);
        
        // Setup event handlers
        setupConnectionHandlers(mongoose.connection);
        
        // Setup performance monitoring
        if (process.env.NODE_ENV === 'production' || process.env.ENABLE_DB_MONITORING === 'true') {
            monitorPerformance();
        }
        
        // Create indexes after connection
        mongoose.connection.once('open', async () => {
            try {
                await ensureIndexes();
            } catch (error) {
                logger.error('Error ensuring indexes:', error);
            }
        });
        
        // Setup slow query logging
        if (process.env.NODE_ENV === 'development' || process.env.LOG_SLOW_QUERIES === 'true') {
            mongoose.set('debug', (collectionName, method, query, doc, options) => {
                const start = Date.now();
                
                process.nextTick(() => {
                    const duration = Date.now() - start;
                    if (duration > 100) {
                        logger.warn(`Slow query detected: ${collectionName}.${method}`, {
                            query,
                            duration: `${duration}ms`,
                            options
                        });
                    }
                });
            });
        }
        
        return mongoose.connection;
    } catch (error) {
        logger.error(`MongoDB connection failed (attempt ${connectionMetrics.connectionAttempts}):`, error);
        
        if (retries > 0) {
            logger.info(`Retrying connection in 5 seconds... (${retries} retries left)`);
            await new Promise(resolve => setTimeout(resolve, 5000));
            return connectDB(retries - 1);
        }
        
        throw error;
    }
};

// Graceful disconnection
const disconnectDB = async () => {
    try {
        // Close all connections in the pool
        await mongoose.connection.close();
        logger.info('MongoDB connection closed gracefully');
    } catch (error) {
        logger.error('Error closing MongoDB connection:', error);
        throw error;
    }
};

// Export functions and utilities
module.exports = {
    connectDB,
    disconnectDB,
    mongoOptions,
    getPoolStats,
    checkDatabaseHealth,
    connectionMetrics
};