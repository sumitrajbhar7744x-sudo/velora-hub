const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss');
const cors = require('cors');

const securityHeaders = helmet({
    contentSecurityPolicy: false,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xssFilter: true,
    noSniff: true,
    hidePoweredBy: true,
});

const corsOptions = {
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Pass'],
};

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 500,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests' },
    skip: function(req) { return req.path.startsWith('/uploads'); }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    message: { error: 'Too many login attempts' },
});

const sanitizeInput = function(req, res, next) {
    var sanitize = function(obj) {
        if (typeof obj === 'string') return xss(obj);
        if (typeof obj === 'object' && obj !== null) {
            Object.keys(obj).forEach(function(key) { obj[key] = sanitize(obj[key]); });
        }
        return obj;
    };
    if (req.body) sanitize(req.body);
    if (req.query) sanitize(req.query);
    next();
};

var failedAttempts = {};
var BLOCK_DURATION = 30 * 60 * 1000;
var MAX_FAILED = 5;

var bruteForceGuard = function(req, res, next) {
    var ip = req.ip;
    var a = failedAttempts[ip];
    if (a && a.blockedUntil && Date.now() < a.blockedUntil) {
        return res.status(429).json({ error: 'IP blocked for ' + Math.ceil((a.blockedUntil - Date.now()) / 60000) + ' min' });
    }
    next();
};

var trackFail = function(ip) {
    if (!failedAttempts[ip]) failedAttempts[ip] = { count: 0, blockedUntil: 0 };
    failedAttempts[ip].count++;
    if (failedAttempts[ip].count >= MAX_FAILED) {
        failedAttempts[ip].blockedUntil = Date.now() + BLOCK_DURATION;
        failedAttempts[ip].count = 0;
    }
};

var resetFail = function(ip) { delete failedAttempts[ip]; };

module.exports = {
    securityHeaders: securityHeaders,
    corsOptions: corsOptions,
    globalLimiter: globalLimiter,
    authLimiter: authLimiter,
    sanitizeInput: sanitizeInput,
    bruteForceGuard: bruteForceGuard,
    trackFail: trackFail,
    resetFail: resetFail
};
