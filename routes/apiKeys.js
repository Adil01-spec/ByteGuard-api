const express = require('express');
const router = express.Router();
const apiKeyController = require('../controllers/apiKeyController');
const authMiddleware = require('../middleware/authMiddleware');

// All key management routes require JWT auth
router.post('/generate', authMiddleware, apiKeyController.generate);
router.get('/list', authMiddleware, apiKeyController.list);
router.delete('/:id/revoke', authMiddleware, apiKeyController.revoke);

module.exports = router;
