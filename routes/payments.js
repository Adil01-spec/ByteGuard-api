const express = require('express');
const router = express.Router();
const paymentController = require('../controllers/paymentController');
const authMiddleware = require('../middleware/authMiddleware');

// Public routes
router.get('/rates', paymentController.getCurrencyRates);

// User routes
router.post('/submit', authMiddleware, paymentController.submitRequest);
router.get('/my-requests', authMiddleware, paymentController.getMyRequests);

// Admin routes
router.get('/admin/requests', authMiddleware, paymentController.getAdminRequests);
router.get('/admin/stats', authMiddleware, paymentController.getAdminStats);
router.post('/admin/:id/approve', authMiddleware, paymentController.approveRequest);
router.post('/admin/:id/reject', authMiddleware, paymentController.rejectRequest);

module.exports = router;
