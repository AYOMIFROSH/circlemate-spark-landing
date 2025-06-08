const Waitlist = require('../models/waitListModel');
const createError = require('../utils/appError');
const logger = require('../utils/logger');
const { Parser } = require('json2csv');
const NodeCache = require('node-cache');

// Initialize cache with 5 minute TTL
const waitlistCache = new NodeCache({ stdTTL: 300, checkperiod: 60 });

// Helper function to generate cache key
const getCacheKey = (query, page, limit, sortBy, order) => {
    return `waitlist_${JSON.stringify(query)}_${page}_${limit}_${sortBy}_${order}`;
};

// Submit waitlist entry
exports.submitWaitlist = async (req, res, next) => {
    try {
        const { firstName, lastName, email, interest } = req.body;

        // Validation
        if (!firstName || !lastName || !email || !interest) {
            return next(new createError('All fields are required', 400));
        }

        // Check if email already exists
        const existingEntry = await Waitlist.findOne({ email: email.toLowerCase() });
        if (existingEntry) {
            return res.status(400).json({
                status: 'error',
                message: 'This email is already on our waitlist!'
            });
        }

        // Create new waitlist entry
        const newEntry = new Waitlist({
            firstName,
            lastName,
            email: email.toLowerCase(),
            interest
        });

        await newEntry.save();

        // Clear cache when new entry is added
        waitlistCache.flushAll();

        logger.info(`New waitlist entry: ${email}`);

        // You can add email notification here if needed
        // await sendWaitlistConfirmationEmail(email, firstName);

        res.status(201).json({
            status: 'success',
            message: 'Thank you for joining our waitlist! We\'ll notify you as soon as we launch.',
            data: {
                id: newEntry._id,
                firstName: newEntry.firstName,
                lastName: newEntry.lastName,
                email: newEntry.email,
                interest: newEntry.interest
            }
        });

    } catch (error) {
        logger.error('Waitlist submission error:', error);
        if (error.code === 11000) {
            return next(new createError('This email is already on our waitlist!', 400));
        }
        next(error);
    }
};

// Get all waitlist entries with optimized fetching and caching
exports.getWaitlist = async (req, res, next) => {
    try {
        const { 
            page = 1, 
            limit = 'all', // Reduced default limit for faster response
            search = '', 
            status = 'all',
            sortBy = 'createdAt',
            order = 'desc' 
        } = req.query;

        // Build query
        let query = {};
        
        if (search) {
            query.$or = [
                { firstName: { $regex: search, $options: 'i' } },
                { lastName: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } }
            ];
        }

        if (status !== 'all') {
            query.status = status;
        }

        // Generate cache key
        const cacheKey = getCacheKey(query, page, limit, sortBy, order);
        
        // Check cache first
        const cachedData = waitlistCache.get(cacheKey);
        if (cachedData) {
            logger.info('Returning cached waitlist data');
            return res.status(200).json(cachedData);
        }

        // Calculate pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const sortOrder = order === 'desc' ? -1 : 1;

        // Use lean() for better performance and select only needed fields
        const [entries, total, stats, totalStats] = await Promise.all([
            Waitlist.find(query)
                .select('firstName lastName email interest status createdAt') // Only select needed fields
                .sort({ [sortBy]: sortOrder })
                .limit(parseInt(limit))
                .skip(skip)
                .lean()
                .exec(),
            Waitlist.countDocuments(query),
            // Aggregate stats only if needed (first page without search)
            page == 1 && !search ? Waitlist.aggregate([
                { $match: query },
                {
                    $group: {
                        _id: '$interest',
                        count: { $sum: 1 }
                    }
                },
                { $sort: { count: -1 } }
            ]) : [],
            page == 1 && !search ? Waitlist.aggregate([
                { $match: query },
                {
                    $group: {
                        _id: '$status',
                        count: { $sum: 1 }
                    }
                }
            ]) : []
        ]);

        const response = {
            status: 'success',
            data: entries,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / parseInt(limit))
            },
            stats: {
                byInterest: stats,
                byStatus: totalStats,
                total
            }
        };

        // Cache the response
        waitlistCache.set(cacheKey, response);

        res.status(200).json(response);

    } catch (error) {
        logger.error('Get waitlist error:', error);
        next(error);
    }
};

// Export waitlist as CSV with streaming for large datasets
exports.exportWaitlist = async (req, res, next) => {
    try {
        // Set headers for file download immediately
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=waitlist.csv');

        // Define CSV fields
        const fields = [
            { label: 'First Name', value: 'firstName' },
            { label: 'Last Name', value: 'lastName' },
            { label: 'Email', value: 'email' },
            { label: 'Interest', value: 'interest' },
            { label: 'Status', value: 'status' },
            { label: 'Joined Date', value: (row) => new Date(row.createdAt).toLocaleString() }
        ];

        // Create CSV parser with fields
        const json2csvParser = new Parser({ fields });

        // Use cursor for streaming large datasets
        const cursor = Waitlist.find({})
            .sort({ createdAt: -1 })
            .lean()
            .cursor();

        let isFirstBatch = true;
        let csvData = '';

        cursor.on('data', (doc) => {
            try {
                const csv = json2csvParser.parse([doc]);
                
                if (isFirstBatch) {
                    csvData = csv; // Include headers
                    isFirstBatch = false;
                } else {
                    // Remove header from subsequent batches
                    csvData = csv.split('\n').slice(1).join('\n');
                }
                
                res.write(csvData + '\n');
            } catch (err) {
                logger.error('Error processing CSV row:', err);
            }
        });

        cursor.on('error', (error) => {
            logger.error('Export cursor error:', error);
            if (!res.headersSent) {
                res.status(500).json({
                    status: 'error',
                    message: 'Error exporting data'
                });
            }
        });

        cursor.on('end', () => {
            res.end();
        });

    } catch (error) {
        logger.error('Export waitlist error:', error);
        next(error);
    }
};

// Update waitlist entry status
exports.updateWaitlistStatus = async (req, res, next) => {
    try {
        const { id } = req.params;
        const { status } = req.body;

        if (!['pending', 'invited', 'joined'].includes(status)) {
            return next(new createError('Invalid status', 400));
        }

        const entry = await Waitlist.findByIdAndUpdate(
            id,
            { 
                status,
                ...(status === 'invited' && { invitedAt: new Date() }),
                ...(status === 'joined' && { joinedAt: new Date() })
            },
            { new: true, runValidators: true }
        );

        if (!entry) {
            return next(new createError('Waitlist entry not found', 404));
        }

        // Clear cache when data is updated
        waitlistCache.flushAll();

        res.status(200).json({
            status: 'success',
            data: entry
        });

    } catch (error) {
        logger.error('Update waitlist status error:', error);
        next(error);
    }
};

// Delete waitlist entry
exports.deleteWaitlistEntry = async (req, res, next) => {
    try {
        const { id } = req.params;

        const entry = await Waitlist.findByIdAndDelete(id);

        if (!entry) {
            return next(new createError('Waitlist entry not found', 404));
        }

        // Clear cache when data is deleted
        waitlistCache.flushAll();

        res.status(200).json({
            status: 'success',
            message: 'Waitlist entry deleted successfully'
        });

    } catch (error) {
        logger.error('Delete waitlist entry error:', error);
        next(error);
    }
};

// Get waitlist statistics with caching
exports.getWaitlistStats = async (req, res, next) => {
    try {
        const cacheKey = 'waitlist_stats';
        
        // Check cache first
        const cachedStats = waitlistCache.get(cacheKey);
        if (cachedStats) {
            return res.status(200).json(cachedStats);
        }

        const stats = await Waitlist.aggregate([
            {
                $facet: {
                    byInterest: [
                        {
                            $group: {
                                _id: '$interest',
                                count: { $sum: 1 }
                            }
                        },
                        { $sort: { count: -1 } }
                    ],
                    byStatus: [
                        {
                            $group: {
                                _id: '$status',
                                count: { $sum: 1 }
                            }
                        }
                    ],
                    byMonth: [
                        {
                            $group: {
                                _id: {
                                    year: { $year: '$createdAt' },
                                    month: { $month: '$createdAt' }
                                },
                                count: { $sum: 1 }
                            }
                        },
                        { $sort: { '_id.year': -1, '_id.month': -1 } },
                        { $limit: 12 }
                    ],
                    total: [
                        { $count: 'count' }
                    ]
                }
            }
        ]).allowDiskUse(true); // Allow disk use for large aggregations

        const response = {
            status: 'success',
            data: {
                byInterest: stats[0].byInterest,
                byStatus: stats[0].byStatus,
                byMonth: stats[0].byMonth,
                total: stats[0].total[0]?.count || 0
            }
        };

        // Cache the stats
        waitlistCache.set(cacheKey, response);

        res.status(200).json(response);

    } catch (error) {
        logger.error('Get waitlist stats error:', error);
        next(error);
    }
};