const express = require('express')
const app = express()

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'ByteGuard API running' })
})

app.all('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' })
})

module.exports = app
