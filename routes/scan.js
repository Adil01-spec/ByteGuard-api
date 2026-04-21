const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/authMiddleware');
const { runScan, getScanHistory, getScanById } = require('../controllers/scanController');

// All scan routes require authentication
router.use(authMiddleware);

// POST /api/scan
router.post('/', runScan);

// GET /api/scan/history
router.get('/history', getScanHistory);

// GET /api/scan/:id
router.get('/:id', getScanById);

module.exports = router;
