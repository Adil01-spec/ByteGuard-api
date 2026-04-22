const supabase = require('../config/supabase');
const logger = require('../utils/logger');
const { scanSsl } = require('../services/sslScanner');

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
  expiryThreshold.setDate(expiryThreshold.getDate() - 7);

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
        await supabase.from('notifications').delete().eq('domain_id', d.id);
        await supabase.from('scans').delete().eq('domain_id', d.id);
        await supabase.from('domains').delete().eq('id', d.id);
      }
    }
  } catch (err) {
    logger.error('Error during domain auto-expiry job:', err);
  }
};

const runSSLCheck = async () => {
  logger.info('Running SSL expiry warnings check...');
  try {
    const { data: domains, error } = await supabase
      .from('domains')
      .select('id, domain, user_id')
      .eq('is_verified', true);

    if (error) throw error;

    for (const d of domains) {
      const sslResult = await scanSsl(d.domain);
      if (sslResult.sslDetails && sslResult.sslDetails.daysRemaining <= 7) {
        await supabase.from('notifications').insert({
          user_id: d.user_id,
          domain_id: d.id,
          message: `Warning: SSL certificate for ${d.domain} expires in ${sslResult.sslDetails.daysRemaining} days!`
        });
      }
    }
  } catch (err) {
    logger.error('Error during SSL expiry warning job:', err);
  }
};

exports.runCrons = async (req, res) => {
  // Verify CRON_SECRET if present (Vercel adds this header)
  const authHeader = req.headers['authorization'];
  if (process.env.CRON_SECRET && authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  logger.info('Cron job triggered via endpoint');
  
  // Run all tasks
  // We can run them concurrently or sequentially
  await Promise.all([
    runSubscriptionCheck(),
    runDomainAutoExpiry(),
    runSSLCheck()
  ]);

  res.json({ status: 'success', message: 'Cron jobs executed' });
};
