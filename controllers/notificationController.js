const supabase = require('../config/supabase');

// ─── GET /api/notifications ───────────────────────────────────
exports.getUnread = async (req, res, next) => {
  try {
    const userId = req.user.id;

    const { data: notifications, error } = await supabase
      .from('notifications')
      .select('*')
      .eq('user_id', userId)
      .eq('is_read', false)
      .order('created_at', { ascending: false });

    if (error) throw error;

    return res.status(200).json({ notifications, count: notifications.length });
  } catch (err) {
    next(err);
  }
};

// ─── PATCH /api/notifications/:id/read ────────────────────────
exports.markAsRead = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;

    // Ensure the notification belongs to this user
    const { data: updated, error } = await supabase
      .from('notifications')
      .update({ is_read: true })
      .eq('id', id)
      .eq('user_id', userId)
      .select()
      .single();

    if (error) {
      // .single() throws if no row matched
      return res.status(404).json({ error: 'Notification not found or does not belong to you.' });
    }

    return res.status(200).json({ message: 'Notification marked as read.', notification: updated });
  } catch (err) {
    next(err);
  }
};
