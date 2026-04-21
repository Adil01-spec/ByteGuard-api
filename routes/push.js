const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/authMiddleware');
const { subscribe, unsubscribe, getVapidPublicKey, testPush } = require('../controllers/pushController');

// GET /api/push/vapid-public-key
router.get('/vapid-public-key', getVapidPublicKey);

// The rest require authentication
router.use(authMiddleware);

// POST /api/push/subscribe
router.post('/subscribe', subscribe);

// DELETE /api/push/unsubscribe
router.delete('/unsubscribe', unsubscribe);

// POST /api/push/test
router.post('/test', testPush);

module.exports = router;
