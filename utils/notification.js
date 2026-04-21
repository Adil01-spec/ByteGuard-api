const { v4: uuidv4 } = require('uuid');
const supabase = require('../config/supabase');

/**
 * Creates a new notification for a user.
 *
 * @param {string} userId  - UUID of the user to notify
 * @param {string} message - Notification message text
 * @returns {Promise<Object|null>} - The created notification record, or null on failure
 */
async function createNotification(userId, message) {
  const { data, error } = await supabase
    .from('notifications')
    .insert({
      id: uuidv4(),
      user_id: userId,
      message,
      is_read: false,
    })
    .select()
    .single();

  if (error) {
    console.error('Failed to create notification:', error.message);
    return null;
  }

  return data;
}

module.exports = { createNotification };
