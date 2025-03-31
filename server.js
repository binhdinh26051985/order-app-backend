// Environment setup and error handling
require('dotenv').config();

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  }
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
});

// Environment validation
const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_NAME', 'JWT_SECRET'];
requiredEnvVars.forEach(env => {
  if (!process.env[env]) {
    console.error(`Missing required environment variable: ${env}`);
    process.exit(1);
  }
});

console.log('Starting server with environment:', {
  NODE_ENV: process.env.NODE_ENV,
  PORT: process.env.PORT,
  DB_HOST: process.env.DB_HOST ? 'set' : 'missing',
  DB_PORT: process.env.DB_PORT ? 'set' : 'missing',
  DB_USER: process.env.DB_USER ? 'set' : 'missing',
  DB_NAME: process.env.DB_NAME ? 'set' : 'missing',
  JWT_SECRET: process.env.JWT_SECRET ? 'set' : 'missing',
  DB_SSL: process.env.DB_SSL_CA ? 'configured' : 'missing'
});

// Dependencies
const fs = require('fs');
const path = require('path');
const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

// SSL Configuration
const sslConfig = process.env.DB_SSL_CA ? {
  ca: fs.readFileSync(path.resolve(process.env.DB_SSL_CA))
} : null;

// Database connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306, // Default MySQL port
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: sslConfig,
  supportBigNumbers: true,
  bigNumberStrings: true,
  timezone: '+00:00'
});

// Express setup
const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE']
}));

// Request logging
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
});

// Database connection test
async function testDatabaseConnection() {
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.ping();
    console.log('Successfully connected to database');
    
    const [rows] = await connection.query(`
      SELECT COUNT(*) as table_count 
      FROM information_schema.tables 
      WHERE table_schema = ? 
      AND table_name IN ('users', 'orders')
    `, [process.env.DB_NAME]);
    
    if (rows[0].table_count !== 2) {
      console.warn('Warning: Some database tables might be missing');
    }
  } catch (err) {
    console.error('Database connection failed:', err);
    throw err; // Rethrow to be caught by startup handler
  } finally {
    if (connection) connection.release();
  }
}

// JWT authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Authorization token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// Routes

// Health check
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.status(200).json({ 
      status: 'healthy',
      database: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({
      status: 'unhealthy',
      database: 'disconnected',
      error: err.message
    });
  }
});

// Database connectivity test
app.get('/db-check', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT 1 + 1 AS result');
    res.json({ 
      status: 'success',
      database: 'connected',
      result: rows[0].result,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Database Connection Test Failed:', err);
    res.status(500).json({
      status: 'error',
      database: 'disconnected',
      error: err.message,
      code: err.code,
      timestamp: new Date().toISOString()
    });
  }
});

// User registration
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const [users] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);
    if (users.length > 0) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword]
    );

    res.status(201).json({ 
      message: 'User registered successfully',
      userId: result.insertId
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

// User login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ 
      token,
      userId: user.id,
      expiresIn: 3600
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Failed to authenticate' });
  }
});

// Order endpoints
app.get('/orders', authenticateToken, async (req, res) => {
  try {
    const [orders] = await pool.query('SELECT * FROM orders WHERE user_id = ?', [req.user.id]);
    res.json(orders);
  } catch (err) {
    console.error('Get orders error:', err);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

app.post('/orders', authenticateToken, async (req, res) => {
  try {
    const { order_details } = req.body;
    if (!order_details) {
      return res.status(400).json({ error: 'Order details are required' });
    }

    const [result] = await pool.query(
      'INSERT INTO orders (user_id, order_details) VALUES (?, ?)',
      [req.user.id, order_details]
    );

    res.status(201).json({
      id: result.insertId,
      user_id: req.user.id,
      order_details,
      created_at: new Date().toISOString()
    });
  } catch (err) {
    console.error('Create order error:', err);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  console.error(`Error ${statusCode}:`, err.message, err.stack);
  
  res.status(statusCode).json({
    error: err.message || 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// Server startup
const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    await testDatabaseConnection();
    
    const server = app.listen(PORT, () => {
      console.log(`Server running on http://localhost:${PORT}`);
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      console.log('SIGTERM received. Shutting down gracefully');
      server.close(() => {
        console.log('Server closed');
        pool.end();
        process.exit(0);
      });
    });
  } catch (err) {
    console.error('Server startup failed:', err);
    process.exit(1);
  }
}

startServer();

// Export for Vercel serverless
module.exports = app;
