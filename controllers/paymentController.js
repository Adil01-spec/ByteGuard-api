const supabase = require('../config/supabase');
const logger = require('../utils/logger');
const currencyService = require('../services/currencyService');

// Verify if a user is an admin
const isAdmin = async (userId) => {
  const { data, error } = await supabase
    .from('admins')
    .select('id')
    .eq('id', userId)
    .maybeSingle();
  
  if (error || !data) return false;
  return true;
};

exports.getCurrencyRates = async (req, res) => {
  try {
    const rates = await currencyService.getRates();
    res.json(rates);
  } catch (err) {
    logger.error('Failed to get currency rates', err);
    res.status(500).json({ error: 'Failed to fetch currency rates' });
  }
};

exports.submitRequest = async (req, res) => {
  try {
    const userId = req.user.id;
    const { plan, plan_type, amount_usd, amount_local, currency_code, payment_method, reference_number, proof_notes } = req.body;

    if (!payment_method || !reference_number) {
      return res.status(400).json({ error: 'Payment method and reference number are required' });
    }

    const { data, error } = await supabase
      .from('payment_requests')
      .insert({
        user_id: userId,
        plan,
        plan_type,
        amount_usd,
        amount_local,
        currency_code,
        payment_method,
        reference_number,
        proof_notes,
        status: 'pending'
      })
      .select()
      .single();

    if (error) throw error;
    res.status(201).json(data);
  } catch (err) {
    logger.error('Error submitting payment request:', err);
    res.status(500).json({ error: 'Failed to submit payment request' });
  }
};

exports.getMyRequests = async (req, res) => {
  try {
    const userId = req.user.id;
    const { data, error } = await supabase
      .from('payment_requests')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data);
  } catch (err) {
    logger.error('Error getting my payment requests:', err);
    res.status(500).json({ error: 'Failed to get payment requests' });
  }
};

// --- Admin Endpoints ---

exports.getAdminStats = async (req, res) => {
  try {
    const isUserAdmin = await isAdmin(req.user.id);
    if (!isUserAdmin) return res.status(403).json({ error: 'Requires admin privileges' });

    // Pending requests
    const { count: pendingCount, error: err1 } = await supabase
      .from('payment_requests')
      .select('id', { count: 'exact' })
      .eq('status', 'pending');

    // Active plans
    const { count: activeCount, error: err2 } = await supabase
      .from('users')
      .select('id', { count: 'exact' })
      .neq('plan', 'free'); // or plan = 'pro'

    // Revenue this month (using approved requests amount_usd)
    const startOfMonth = new Date();
    startOfMonth.setDate(1);
    startOfMonth.setHours(0,0,0,0);

    const { data: approvedRequests, error: err3 } = await supabase
      .from('payment_requests')
      .select('amount_usd')
      .eq('status', 'approved')
      .gte('updated_at', startOfMonth.toISOString());

    if (err1 || err2 || err3) throw new Error('Error fetching stats');

    const totalRevenue = approvedRequests.reduce((sum, req) => sum + parseFloat(req.amount_usd || 0), 0);

    res.json({
      pendingRequests: pendingCount || 0,
      activePlans: activeCount || 0,
      revenueThisMonth: totalRevenue
    });
  } catch (err) {
    logger.error('Error fetching admin stats:', err);
    res.status(500).json({ error: 'Failed to fetch admin stats' });
  }
};

exports.getAdminRequests = async (req, res) => {
  try {
    const isUserAdmin = await isAdmin(req.user.id);
    if (!isUserAdmin) return res.status(403).json({ error: 'Requires admin privileges' });

    const { data, error } = await supabase
      .from('payment_requests')
      .select(`
        *,
        users (email)
      `)
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data);
  } catch (err) {
    logger.error('Error fetching all payment requests for admin:', err);
    res.status(500).json({ error: 'Failed to fetch payment requests' });
  }
};

exports.approveRequest = async (req, res) => {
  try {
    const isUserAdmin = await isAdmin(req.user.id);
    if (!isUserAdmin) return res.status(403).json({ error: 'Requires admin privileges' });

    const { id } = req.params;

    // Get the request
    const { data: requestRow, error: reqErr } = await supabase
      .from('payment_requests')
      .select('user_id, plan, status')
      .eq('id', id)
      .single();

    if (reqErr || !requestRow) return res.status(404).json({ error: 'Request not found' });
    if (requestRow.status !== 'pending') return res.status(400).json({ error: 'Request is already processed' });

    // Update request status
    const { error: updErr } = await supabase
      .from('payment_requests')
      .update({ status: 'approved', updated_at: new Date().toISOString() })
      .eq('id', id);

    if (updErr) throw updErr;

    // Upate user's plan and expiry (30 days from now)
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30);

    const { error: userErr } = await supabase
      .from('users')
      .update({ plan: requestRow.plan, plan_expires_at: expiresAt.toISOString() })
      .eq('id', requestRow.user_id);

    if (userErr) throw userErr;

    // Create a notification for the user
    await supabase.from('notifications').insert({
      user_id: requestRow.user_id,
      message: `Your payment for the ${requestRow.plan.toUpperCase()} plan has been approved. Your plan is now active.`
    });

    res.json({ message: 'Payment approved successfully' });
  } catch (err) {
    logger.error('Error approving payment request:', err);
    res.status(500).json({ error: 'Failed to approve payment request' });
  }
};

exports.rejectRequest = async (req, res) => {
  try {
    const isUserAdmin = await isAdmin(req.user.id);
    if (!isUserAdmin) return res.status(403).json({ error: 'Requires admin privileges' });

    const { id } = req.params;

    const { data: requestRow, error: reqErr } = await supabase
      .from('payment_requests')
      .select('user_id, status')
      .eq('id', id)
      .single();

    if (reqErr || !requestRow) return res.status(404).json({ error: 'Request not found' });
    if (requestRow.status !== 'pending') return res.status(400).json({ error: 'Request is already processed' });

    const { error: updErr } = await supabase
      .from('payment_requests')
      .update({ status: 'rejected', updated_at: new Date().toISOString() })
      .eq('id', id);

    if (updErr) throw updErr;

    await supabase.from('notifications').insert({
      user_id: requestRow.user_id,
      message: `Your recent payment request was rejected. Please review your details and submit again if necessary.`
    });

    res.json({ message: 'Payment rejected successfully' });
  } catch (err) {
    logger.error('Error rejecting payment request:', err);
    res.status(500).json({ error: 'Failed to reject payment request' });
  }
};
