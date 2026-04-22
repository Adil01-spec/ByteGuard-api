require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error('WARNING: Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in environment variables.');
  console.error('Available env keys:', Object.keys(process.env).filter(k => k.startsWith('SUPA')));
}

const supabase = supabaseUrl && supabaseKey
  ? createClient(supabaseUrl, supabaseKey)
  : null;

if (supabase) {
  console.log('Supabase connected');
} else {
  console.error('Supabase client NOT created — missing credentials');
}

module.exports = supabase;
