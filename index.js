require('dotenv').config();
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
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

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Site Guardian API is running' });
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

const supabase = require('./config/supabase');
const logger = require('./utils/logger');

const runSubscriptionCheck = async () => {
  logger.info('Running subscription expiry check...');
  const now = new Date();
  const next7Days = new Date();
  next7Days.setDate(next7Days.getDate() + 7);

  try {
    // 1. Find users whose plan expires in next 7 days and are active (pro)
    const { data: expiringUsers, error: expErr } = await supabase
      .from('users')
      .select('id, email, plan_expires_at')
      .eq('plan', 'pro')
      .lt('plan_expires_at', next7Days.toISOString())
      .gt('plan_expires_at', now.toISOString());

    if (expiringUsers && expiringUsers.length > 0) {
      for (const u of expiringUsers) {
        const diffMs = new Date(u.plan_expires_at) - now;
        const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));
        await supabase.from('notifications').insert({
          user_id: u.id,
          message: `Your Pro plan expires in ${diffDays} days — please renew to avoid losing access.`
        });
      }
    }

    // 2. Find users whose plan has already expired
    const { data: expiredUsers, error: expdErr } = await supabase
      .from('users')
      .select('id, email, plan_expires_at')
      .eq('plan', 'pro')
      .lt('plan_expires_at', now.toISOString());

    if (expiredUsers && expiredUsers.length > 0) {
      for (const u of expiredUsers) {
        await supabase.from('users').update({ plan: 'free' }).eq('id', u.id);
        await supabase.from('notifications').insert({
          user_id: u.id,
          message: 'Your Pro plan has expired. Your account has been moved to the free plan.'
        });
      }
    }
  } catch (err) {
    logger.error('Error during subscription check job:', err);
  }
};

const runDomainAutoExpiry = async () => {
  logger.info('Running domain auto-expiry check...');
  const now = new Date();
  const expiryThreshold = new Date();
  expiryThreshold.setDate(expiryThreshold.getDate() - 7); // Default 7 days ago

  try {
    const { data: expiredDomains, error } = await supabase
      .from('domains')
      .select('id, domain, user_id')
      .eq('is_verified', false)
      .lt('created_at', expiryThreshold.toISOString());

    if (error) throw error;

    if (expiredDomains && expiredDomains.length > 0) {
      for (const d of expiredDomains) {
        logger.info(`Auto-deleting expired unverified domain: ${d.domain} (User: ${d.user_id})`);
        // Proceed to delete (also clean up notifications/scans just in case)
        await supabase.from('notifications').delete().eq('domain_id', d.id);
        await supabase.from('scans').delete().eq('domain_id', d.id);
        await supabase.from('domains').delete().eq('id', d.id);
      }
    }
  } catch (err) {
    logger.error('Error during domain auto-expiry job:', err);
  }
};

app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  await require('./services/currencyService').initialize();
  runSubscriptionCheck(); // Run immediate
  runDomainAutoExpiry(); // Run immediate
  setInterval(runSubscriptionCheck, 24 * 60 * 60 * 1000); // And every 24hr
  setInterval(runDomainAutoExpiry, 1 * 60 * 60 * 1000); // And every 1hr
});

module.exports = app;
