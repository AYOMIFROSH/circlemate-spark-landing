const redis = require('redis');
const logger = require('./logger');
require('dotenv').config();

// Redis configuration
const redisConfig = {
    socket: {
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
        reconnectStrategy: (retries) => {
            if (retries > 10) {
                logger.error('Redis: Max reconnection attempts reached');
                return new Error('Max reconnection attempts reached');
            }
            const delay = Math.min(retries * 100, 3000);
            logger.info(`Redis: Reconnecting in ${delay}ms... (attempt ${retries})`);
            return delay;
        },
        connectTimeout: 10000,
        keepAlive: 5000
    },
    username: process.env.REDIS_USERNAME || 'default',
    password: process.env.REDIS_PASSWORD,
    database: process.env.REDIS_DB || 0,
    
    // Performance options
    lazyConnect: false,
    
    // Command timeout
    commandsQueueMaxLength: 100,
    
    // Enable offline queue
    enableOfflineQueue: true,
    
    // Readonly mode for replicas
    readOnly: false,
    
    // Automatic pipelining for better performance
    enableAutoPipelining: true,
    autoPipeliningIgnoredCommands: ['info', 'ping', 'flushdb']
};

// Create Redis client
const client = redis.createClient(redisConfig);

// Error handling
client.on('error', (err) => {
    logger.error('Redis Client Error:', err);
});

client.on('connect', () => {
    logger.info('Redis Client Connected');
});

client.on('ready', () => {
    logger.info('Redis Client Ready');
});

client.on('reconnecting', () => {
    logger.warn('Redis Client Reconnecting...');
});

client.on('end', () => {
    logger.info('Redis Client Connection Closed');
});

// Connect to Redis
(async () => {
    try {
        await client.connect();
    } catch (error) {
        logger.error('Failed to connect to Redis:', error);
    }
})();

// Wrapper functions with error handling
const redisWrapper = {
    // Basic operations
    async get(key) {
        try {
            return await client.get(key);
        } catch (error) {
            logger.error(`Redis GET error for key ${key}:`, error);
            return null;
        }
    },

    async set(key, value, options = {}) {
        try {
            if (options.EX) {
                return await client.set(key, value, { EX: options.EX });
            }
            return await client.set(key, value);
        } catch (error) {
            logger.error(`Redis SET error for key ${key}:`, error);
            return null;
        }
    },

    async setex(key, seconds, value) {
        try {
            return await client.setEx(key, seconds, value);
        } catch (error) {
            logger.error(`Redis SETEX error for key ${key}:`, error);
            return null;
        }
    },

    async del(key) {
        try {
            return await client.del(key);
        } catch (error) {
            logger.error(`Redis DEL error for key ${key}:`, error);
            return 0;
        }
    },

    async incr(key) {
        try {
            return await client.incr(key);
        } catch (error) {
            logger.error(`Redis INCR error for key ${key}:`, error);
            return null;
        }
    },

    async expire(key, seconds) {
        try {
            return await client.expire(key, seconds);
        } catch (error) {
            logger.error(`Redis EXPIRE error for key ${key}:`, error);
            return false;
        }
    },

    async ttl(key) {
        try {
            return await client.ttl(key);
        } catch (error) {
            logger.error(`Redis TTL error for key ${key}:`, error);
            return -1;
        }
    },

    // Hash operations
    async hset(key, field, value) {
        try {
            return await client.hSet(key, field, value);
        } catch (error) {
            logger.error(`Redis HSET error for key ${key}:`, error);
            return null;
        }
    },

    async hget(key, field) {
        try {
            return await client.hGet(key, field);
        } catch (error) {
            logger.error(`Redis HGET error for key ${key}:`, error);
            return null;
        }
    },

    async hgetall(key) {
        try {
            return await client.hGetAll(key);
        } catch (error) {
            logger.error(`Redis HGETALL error for key ${key}:`, error);
            return {};
        }
    },

    // List operations
    async lpush(key, ...values) {
        try {
            return await client.lPush(key, values);
        } catch (error) {
            logger.error(`Redis LPUSH error for key ${key}:`, error);
            return null;
        }
    },

    async lrange(key, start, stop) {
        try {
            return await client.lRange(key, start, stop);
        } catch (error) {
            logger.error(`Redis LRANGE error for key ${key}:`, error);
            return [];
        }
    },

    async ltrim(key, start, stop) {
        try {
            return await client.lTrim(key, start, stop);
        } catch (error) {
            logger.error(`Redis LTRIM error for key ${key}:`, error);
            return null;
        }
    },

    // Set operations
    async sadd(key, ...members) {
        try {
            return await client.sAdd(key, members);
        } catch (error) {
            logger.error(`Redis SADD error for key ${key}:`, error);
            return null;
        }
    },

    async smembers(key) {
        try {
            return await client.sMembers(key);
        } catch (error) {
            logger.error(`Redis SMEMBERS error for key ${key}:`, error);
            return [];
        }
    },

    async sismember(key, member) {
        try {
            return await client.sIsMember(key, member);
        } catch (error) {
            logger.error(`Redis SISMEMBER error for key ${key}:`, error);
            return false;
        }
    },

    // Utility functions
    async exists(key) {
        try {
            return await client.exists(key);
        } catch (error) {
            logger.error(`Redis EXISTS error for key ${key}:`, error);
            return 0;
        }
    },

    async keys(pattern) {
        try {
            return await client.keys(pattern);
        } catch (error) {
            logger.error(`Redis KEYS error for pattern ${pattern}:`, error);
            return [];
        }
    },

    async flushdb() {
        try {
            if (process.env.NODE_ENV === 'production') {
                logger.warn('Attempted to flush Redis DB in production - operation blocked');
                return null;
            }
            return await client.flushDb();
        } catch (error) {
            logger.error('Redis FLUSHDB error:', error);
            return null;
        }
    },

    // Pipeline for batch operations
    multi() {
        return client.multi();
    },

    // Pub/Sub
    async subscribe(channel, callback) {
        try {
            const subscriber = client.duplicate();
            await subscriber.connect();
            await subscriber.subscribe(channel, callback);
            return subscriber;
        } catch (error) {
            logger.error(`Redis SUBSCRIBE error for channel ${channel}:`, error);
            return null;
        }
    },

    async publish(channel, message) {
        try {
            return await client.publish(channel, message);
        } catch (error) {
            logger.error(`Redis PUBLISH error for channel ${channel}:`, error);
            return 0;
        }
    },

    // Advanced caching functions
    async getOrSet(key, fallbackFn, ttl = 300) {
        try {
            let value = await this.get(key);
            if (value === null) {
                value = await fallbackFn();
                if (value !== null && value !== undefined) {
                    await this.setex(key, ttl, JSON.stringify(value));
                }
                return value;
            }
            return JSON.parse(value);
        } catch (error) {
            logger.error(`Redis getOrSet error for key ${key}:`, error);
            return await fallbackFn();
        }
    },

    // Cache invalidation patterns
    async invalidatePattern(pattern) {
        try {
            const keys = await this.keys(pattern);
            if (keys.length > 0) {
                await client.del(keys);
                logger.info(`Invalidated ${keys.length} keys matching pattern: ${pattern}`);
            }
            return keys.length;
        } catch (error) {
            logger.error(`Redis invalidatePattern error for pattern ${pattern}:`, error);
            return 0;
        }
    },

    // Rate limiting helper
    async checkRateLimit(key, limit, window) {
        try {
            const current = await this.incr(key);
            if (current === 1) {
                await this.expire(key, window);
            }
            return {
                allowed: current <= limit,
                current,
                remaining: Math.max(0, limit - current),
                resetIn: await this.ttl(key)
            };
        } catch (error) {
            logger.error(`Redis checkRateLimit error for key ${key}:`, error);
            return { allowed: true, current: 0, remaining: limit, resetIn: 0 };
        }
    },

    // Distributed lock implementation
    async acquireLock(resource, ttl = 10) {
        const lockKey = `lock:${resource}`;
        const lockId = Math.random().toString(36).substring(2);
        
        try {
            const result = await client.set(lockKey, lockId, {
                NX: true,
                EX: ttl
            });
            
            if (result === 'OK') {
                return {
                    acquired: true,
                    lockId,
                    release: async () => {
                        const currentValue = await this.get(lockKey);
                        if (currentValue === lockId) {
                            await this.del(lockKey);
                        }
                    }
                };
            }
            
            return { acquired: false };
        } catch (error) {
            logger.error(`Redis acquireLock error for resource ${resource}:`, error);
            return { acquired: false };
        }
    },

    // Session storage helpers
    async getSession(sessionId) {
        try {
            const data = await this.get(`session:${sessionId}`);
            return data ? JSON.parse(data) : null;
        } catch (error) {
            logger.error(`Redis getSession error for session ${sessionId}:`, error);
            return null;
        }
    },

    async setSession(sessionId, data, ttl = 1800) { // 30 minutes default
        try {
            return await this.setex(`session:${sessionId}`, ttl, JSON.stringify(data));
        } catch (error) {
            logger.error(`Redis setSession error for session ${sessionId}:`, error);
            return null;
        }
    },

    async deleteSession(sessionId) {
        try {
            return await this.del(`session:${sessionId}`);
        } catch (error) {
            logger.error(`Redis deleteSession error for session ${sessionId}:`, error);
            return 0;
        }
    },

    // Monitoring and stats
    async getStats() {
        try {
            const info = await client.info('stats');
            const memory = await client.info('memory');
            return { stats: info, memory };
        } catch (error) {
            logger.error('Redis getStats error:', error);
            return null;
        }
    }
};

// Graceful shutdown
const gracefulShutdown = async () => {
    try {
        await client.quit();
        logger.info('Redis connection closed gracefully');
    } catch (error) {
        logger.error('Error closing Redis connection:', error);
    }
};

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

module.exports = redisWrapper;