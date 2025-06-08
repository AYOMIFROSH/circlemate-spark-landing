// utils/networkMiddleware.js
const dns = require('dns').promises;
const logger = require('./logger');

// Cache for network status
let isNetworkAvailable = true;
let lastNetworkCheck = Date.now();
const NETWORK_CHECK_INTERVAL = 5000; // 5 seconds

// Check network connectivity
const checkNetworkConnectivity = async () => {
    try {
        // Try to resolve multiple DNS servers for reliability
        const dnsServers = [
            '8.8.8.8',     // Google DNS
            '1.1.1.1',     // Cloudflare DNS
            '208.67.222.222' // OpenDNS
        ];

        const results = await Promise.allSettled(
            dnsServers.map(server => 
                dns.resolve4('google.com', { 
                    servers: [server],
                    timeout: 3000 
                })
            )
        );

        // If at least one DNS resolution succeeds, we have internet
        const hasInternet = results.some(result => result.status === 'fulfilled');
        
        isNetworkAvailable = hasInternet;
        lastNetworkCheck = Date.now();
        
        return hasInternet;
    } catch (error) {
        logger.error('Network connectivity check failed:', error);
        isNetworkAvailable = false;
        lastNetworkCheck = Date.now();
        return false;
    }
};

// Middleware to check network connectivity
exports.networkCheck = async (req, res, next) => {
    try {
        // Skip network check for certain routes
        const skipRoutes = ['/health', '/api/health', '/favicon.ico', '/favicon.png'];
        if (skipRoutes.some(route => req.path.includes(route))) {
            return next();
        }

        // Check if we need to update network status
        const now = Date.now();
        if (now - lastNetworkCheck > NETWORK_CHECK_INTERVAL) {
            await checkNetworkConnectivity();
        }

        // If network is not available, return error immediately
        if (!isNetworkAvailable) {
            // Try one more time in case it's a temporary issue
            const isConnected = await checkNetworkConnectivity();
            
            if (!isConnected) {
                logger.warn('No internet connection detected for request:', req.path);
                return res.status(503).json({
                    status: 'FAILED',
                    message: 'No internet connection. Please check your connection and try again.',
                    error: 'NETWORK_UNAVAILABLE',
                    timestamp: new Date().toISOString()
                });
            }
        }

        next();
    } catch (error) {
        // If network check itself fails, assume network is available and continue
        logger.error('Network check middleware error:', error);
        next();
    }
};

// Wrapper for external API calls with network error handling
exports.withNetworkErrorHandling = (asyncFn) => {
    return async (...args) => {
        try {
            return await asyncFn(...args);
        } catch (error) {
            // Check if it's a network-related error
            if (isNetworkError(error)) {
                logger.error('Network error detected:', error.message);
                
                // Update network status
                isNetworkAvailable = false;
                lastNetworkCheck = Date.now();
                
                throw new Error('Network connection error. Please check your internet connection and try again.');
            }
            throw error;
        }
    };
};

// Helper to identify network errors
const isNetworkError = (error) => {
    const networkErrorCodes = [
        'ENOTFOUND',
        'ECONNREFUSED',
        'ECONNRESET',
        'ETIMEDOUT',
        'EHOSTUNREACH',
        'ENETUNREACH',
        'ENETDOWN',
        'EPIPE',
        'ECONNABORTED'
    ];

    return networkErrorCodes.includes(error.code) ||
           error.message.includes('getaddrinfo') ||
           error.message.includes('network') ||
           error.message.includes('ECONNREFUSED');
};

// Axios interceptor for network errors
exports.axiosNetworkInterceptor = (axiosInstance) => {
    // Request interceptor
    axiosInstance.interceptors.request.use(
        async (config) => {
            // Check network before making request
            if (!isNetworkAvailable || Date.now() - lastNetworkCheck > NETWORK_CHECK_INTERVAL) {
                const hasInternet = await checkNetworkConnectivity();
                if (!hasInternet) {
                    const error = new Error('No internet connection available');
                    error.code = 'NETWORK_UNAVAILABLE';
                    throw error;
                }
            }
            return config;
        },
        (error) => {
            return Promise.reject(error);
        }
    );

    // Response interceptor
    axiosInstance.interceptors.response.use(
        (response) => response,
        (error) => {
            if (isNetworkError(error)) {
                isNetworkAvailable = false;
                lastNetworkCheck = Date.now();
                
                error.message = 'Network connection error. Please check your internet connection and try again.';
                error.isNetworkError = true;
            }
            return Promise.reject(error);
        }
    );
};

// Mongoose connection error handler
exports.mongooseNetworkErrorHandler = (mongoose) => {
    mongoose.connection.on('error', (error) => {
        if (isNetworkError(error)) {
            logger.error('MongoDB network error:', error);
            isNetworkAvailable = false;
            lastNetworkCheck = Date.now();
        }
    });

    mongoose.connection.on('disconnected', () => {
        logger.warn('MongoDB disconnected - checking network connectivity');
        checkNetworkConnectivity();
    });

    mongoose.connection.on('reconnected', () => {
        logger.info('MongoDB reconnected - network connectivity restored');
        isNetworkAvailable = true;
        lastNetworkCheck = Date.now();
    });
};

// Email transporter error handler
exports.emailNetworkErrorHandler = (transporter) => {
    const originalSendMail = transporter.sendMail.bind(transporter);
    
    transporter.sendMail = async function(...args) {
        try {
            return await originalSendMail(...args);
        } catch (error) {
            if (isNetworkError(error)) {
                logger.error('Email network error:', error);
                isNetworkAvailable = false;
                lastNetworkCheck = Date.now();
                
                throw new Error('Unable to send email due to network connectivity issues. Please try again later.');
            }
            throw error;
        }
    };
};

// Export network status getter
exports.getNetworkStatus = () => ({
    isAvailable: isNetworkAvailable,
    lastChecked: new Date(lastNetworkCheck).toISOString()
});

// Initialize network check on module load
checkNetworkConnectivity();