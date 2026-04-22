const express = require('express');
const router = express.Router();
const cronController = require('../controllers/cronController');

router.post('/run', cronController.runCrons);

module.exports = router;
