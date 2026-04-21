// controllers/siteController.js
// Handles site monitoring logic

exports.getSites = async (req, res, next) => {
  try {
    // TODO: fetch sites from Supabase
    res.json({ sites: [] });
  } catch (err) {
    next(err);
  }
};

exports.addSite = async (req, res, next) => {
  try {
    // TODO: add site to Supabase
    res.status(201).json({ message: 'Site added' });
  } catch (err) {
    next(err);
  }
};
