const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authStrictLimiter, globalAuthFailLimiter } = require('../middleware/rateLimiter');

const authMiddleware = require('../middleware/authMiddleware');

// Auth endpoints are wrapped in global failure tracking, and strict login limiting
router.post('/register', globalAuthFailLimiter, authStrictLimiter, authController.register);
router.post('/login', globalAuthFailLimiter, authStrictLimiter, authController.login);
router.get('/me', authMiddleware, authController.me);

module.exports = router;
