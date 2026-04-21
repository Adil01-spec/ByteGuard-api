require('dotenv').config();
const supabase = require('./config/supabase');

async function testConnection() {
  const { data, error } = await supabase.from('users').select('*');

  if (error) {
    console.error('Supabase connection failed:', error.message);
  } else {
    console.log('Supabase connected successfully. Rows fetched:', data.length);
  }
}

testConnection();
