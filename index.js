console.log('Starting ByteGuard API...');

require('dotenv').config();
console.log('ENV loaded');

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
  ].filter(Boolean),
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
console.log('Middleware ready');

// Routes — wrap each in try-catch so one bad route doesn't kill the whole app
try { app.use('/api/auth', require('./routes/auth')); console.log('Route loaded: /api/auth'); } catch (e) { console.error('Failed to load /api/auth:', e.message); }
try { app.use('/api/domains', require('./routes/domains')); console.log('Route loaded: /api/domains'); } catch (e) { console.error('Failed to load /api/domains:', e.message); }
try { app.use('/api/scan', require('./routes/scan')); console.log('Route loaded: /api/scan'); } catch (e) { console.error('Failed to load /api/scan:', e.message); }
try { app.use('/api/notifications', require('./routes/notifications')); console.log('Route loaded: /api/notifications'); } catch (e) { console.error('Failed to load /api/notifications:', e.message); }
try { app.use('/api/keys', require('./routes/apiKeys')); console.log('Route loaded: /api/keys'); } catch (e) { console.error('Failed to load /api/keys:', e.message); }
try { app.use('/api/public', require('./routes/publicScan')); console.log('Route loaded: /api/public'); } catch (e) { console.error('Failed to load /api/public:', e.message); }
try { app.use('/api/payments', require('./routes/payments')); console.log('Route loaded: /api/payments'); } catch (e) { console.error('Failed to load /api/payments:', e.message); }
try { app.use('/api/push', require('./routes/push')); console.log('Route loaded: /api/push'); } catch (e) { console.error('Failed to load /api/push:', e.message); }
try { app.use('/api/cron', require('./routes/cron')); console.log('Route loaded: /api/cron'); } catch (e) { console.error('Failed to load /api/cron:', e.message); }
console.log('Routes mounted');

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'ByteGuard API is running' });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'ByteGuard API running' })
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

// For local development only
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

// For Vercel serverless
module.exports = app;
