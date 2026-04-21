const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/authMiddleware');
const { registerDomain, verifyDns, verifyFile, verifyMeta, getDomains, deleteDomain } = require('../controllers/domainController');

// All domain routes require authentication
router.use(authMiddleware);

// GET /api/domains
router.get('/', getDomains);

// POST /api/domains/register
router.post('/register', registerDomain);

// POST /api/domains/verify/dns
router.post('/verify/dns', verifyDns);

// POST /api/domains/verify/file
router.post('/verify/file', verifyFile);

// POST /api/domains/verify/meta
router.post('/verify/meta', verifyMeta);

// DELETE /api/domains/:id
router.delete('/:id', deleteDomain);

module.exports = router;

