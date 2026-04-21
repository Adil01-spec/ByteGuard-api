const supabase = require('../config/supabase');

exports.subscribe = async (req, res, next) => {
  try {
    const { subscription } = req.body;
    const userId = req.user.id;

    if (!subscription || !subscription.endpoint) {
      return res.status(400).json({ error: 'Valid push subscription is required.' });
    }

    // Check if it already exists for this endpoint to prevent duplicates
    const { data: existing } = await supabase
      .from('push_subscriptions')
      .select('id')
      .eq('user_id', userId)
      .eq('subscription->>endpoint', subscription.endpoint)
      .maybeSingle();

    if (existing) {
      return res.status(200).json({ message: 'Already subscribed.' });
    }

    const { error } = await supabase
      .from('push_subscriptions')
      .insert({
        user_id: userId,
        subscription
      });

    if (error) {
      console.error('Failed to insert push subscription:', error);
      return res.status(500).json({ error: 'Failed to save subscription.' });
    }

    res.status(201).json({ message: 'Subscribed successfully.' });
  } catch (err) {
    next(err);
  }
};

exports.unsubscribe = async (req, res, next) => {
  try {
    const { endpoint } = req.body;
    const userId = req.user.id;

    let query = supabase.from('push_subscriptions').delete().eq('user_id', userId);
    
    if (endpoint) {
      // If endpoint is provided, delete only that specific endpoint device
      query = query.eq('subscription->>endpoint', endpoint);
    } // else delete all subscriptions for the user (could adjust logic based on need)

    const { error } = await query;

    if (error) {
      console.error('Failed to remove push subscription:', error);
      return res.status(500).json({ error: 'Failed to remove subscription.' });
    }

    res.status(200).json({ message: 'Unsubscribed successfully.' });
  } catch (err) {
    next(err);
  }
};

exports.getVapidPublicKey = (req, res) => {
  res.json({ publicKey: process.env.VAPID_PUBLIC_KEY });
};

exports.testPush = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { sendPushNotification } = require('../services/pushService');

    const { data: subs } = await supabase
      .from('push_subscriptions')
      .select('*')
      .eq('user_id', userId);

    if (!subs || subs.length === 0) {
      return res.status(404).json({ error: 'No active push subscriptions found.' });
    }

    for (const sub of subs) {
      await sendPushNotification(sub.subscription, {
        title: 'ByteGuard Test Push',
        body: 'If you see this, push notifications are working completely correctly!',
        icon: '/vite.svg',
        badge: '/vite.svg',
        data: { url: '/dashboard' }
      });
    }

    res.status(200).json({ message: `Sent test push to ${subs.length} device(s)` });
  } catch (err) {
    next(err);
  }
};
