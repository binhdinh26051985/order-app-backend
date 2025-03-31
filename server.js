const fs = require('fs');
const path = require('path');
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
app.use(express.json());

// Configure CORS
const allowedOrigins = [
  'http://localhost:5173',
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
  origin: allowedOrigins,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));

// Database connection with improved SSL handling
let db;
async function initializeDatabase() {
  try {
    let sslOptions = null;
    
    if (process.env.DB_SSL_CA) {
      // For Vercel: Use the environment variable directly
      if (process.env.DB_SSL_CA.includes('BEGIN CERTIFICATE')) {
        sslOptions = { ca: process.env.DB_SSL_CA };
      } 
      // For local development: Read from file
      else if (fs.existsSync(path.join(__dirname, process.env.DB_SSL_CA))) {
        sslOptions = { ca: fs.readFileSync(path.join(__dirname, process.env.DB_SSL_CA)) };
      }
    } else if (process.env.NODE_ENV === 'production') {
      sslOptions = { rejectUnauthorized: true };
    }

    db = mysql.createPool({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      ssl: sslOptions
    });

    // Test connection
    const conn = await db.getConnection();
    conn.release();
    console.log('Database connected successfully');
  } catch (err) {
    console.error('Database connection failed:', err);
    // Exit if DB connection fails in production
    if (process.env.NODE_ENV === 'production') process.exit(1);
  }
}

initializeDatabase();

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Internal server error',
    ...(process.env.NODE_ENV !== 'production' && { details: err.message })
  });
});

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    if (!db) throw new Error('Database not connected');
    await db.query('SELECT 1');
    res.json({ status: 'OK', database: 'connected' });
  } catch (err) {
    res.status(500).json({ status: 'Unhealthy', error: err.message });
  }
});

// [Keep all your existing endpoints unchanged...]
// (Register, Login, Orders endpoints remain the same)

module.exports = app;

if (process.env.VERCEL !== '1') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}
