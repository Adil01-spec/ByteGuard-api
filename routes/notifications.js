const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/authMiddleware');
const { getUnread, markAsRead } = require('../controllers/notificationController');

// All notification routes require authentication
router.use(authMiddleware);

// GET /api/notifications
router.get('/', getUnread);

// PATCH /api/notifications/:id/read
router.patch('/:id/read', markAsRead);

module.exports = router;
