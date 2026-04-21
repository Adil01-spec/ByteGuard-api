// utils/response.js
// Standardized API response helpers

exports.success = (res, data, statusCode = 200) => {
  return res.status(statusCode).json({ success: true, data });
};

exports.error = (res, message, statusCode = 400) => {
  return res.status(statusCode).json({ success: false, error: message });
};
