const webpush = require('web-push');
const supabase = require('../config/supabase');
const logger = require('../utils/logger');

webpush.setVapidDetails(
  process.env.VAPID_EMAIL || 'mailto:support@byteguard.com',
  process.env.VAPID_PUBLIC_KEY,
  process.env.VAPID_PRIVATE_KEY
);

exports.sendPushNotification = async (subscription, payload) => {
  try {
    await webpush.sendNotification(subscription, JSON.stringify(payload));
  } catch (error) {
    if (error.statusCode === 410) {
      // Subscription has expired or is no longer valid
      logger.info('Push subscription expired, removing from database');
      await supabase
        .from('push_subscriptions')
        .delete()
        .contains('subscription', { endpoint: subscription.endpoint });
    } else {
      logger.error('Error sending push notification:', error);
    }
  }
};

exports.sendScanCompleteNotification = async (userSubscriptions, scanData, notificationId) => {
  const payload = {
    title: 'ByteGuard Scan Complete',
    body: `${scanData.domain} — ${scanData.risk_score.toUpperCase()}: ${scanData.issues_count} issues found`,
    icon: '/vite.svg',
    badge: '/vite.svg',
    data: {
      scanId: scanData.id,
      notificationId: notificationId
    },
    tag: `scan-${scanData.id}`
  };

  for (const sub of userSubscriptions) {
    await exports.sendPushNotification(sub.subscription, payload);
  }
};

exports.sendCriticalAlertNotification = async (userSubscriptions, finding, scanId, notificationId) => {
  const payload = {
    title: '🚨 Critical Vulnerability Found',
    body: typeof finding === 'string' ? finding : finding.description || finding.title || 'Critical security issue detected.',
    icon: '/vite.svg',
    badge: '/vite.svg',
    data: {
      scanId: scanId,
      notificationId: notificationId
    },
    tag: `critical-${scanId}-${Math.random()}`
  };

  for (const sub of userSubscriptions) {
    await exports.sendPushNotification(sub.subscription, payload);
  }
};
