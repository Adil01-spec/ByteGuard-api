require('dotenv').config();
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://localhost:4173',
    process.env.CLIENT_URL
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/domains', require('./routes/domains'));
app.use('/api/scan', require('./routes/scan'));
app.use('/api/notifications', require('./routes/notifications'));
app.use('/api/keys', require('./routes/apiKeys'));
app.use('/api/public', require('./routes/publicScan'));
app.use('/api/payments', require('./routes/payments'));
app.use('/api/push', require('./routes/push'));
app.use('/api/cron', require('./routes/cron'));

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'ByteGuard API is running' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
  });
});

if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, async () => {
    console.log(`Server running on port ${PORT}`);
    try {
      await require('./services/currencyService').initialize();
    } catch (err) {
      console.error('Failed to initialize currency service:', err);
    }
  });
}

module.exports = app;

