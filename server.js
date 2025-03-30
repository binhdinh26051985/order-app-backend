process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  }
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
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

const fs = require('fs');
const path = require('path');
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise'); // Using promise-based API
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();

// Enhanced CORS configuration
const allowedOrigins = [
  'http://localhost:5173',
  'https://your-production-frontend.com'
];

app.use(express.json());
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`The CORS policy blocks access from ${origin}`));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// SSL Configuration
let sslConfig;
try {
  if (process.env.DB_SSL_CERT_CONTENT) {
    // For Vercel - use environment variable with certificate content
    sslConfig = {
      ca: Buffer.from(process.env.DB_SSL_CERT_CONTENT, 'base64').toString(),
      rejectUnauthorized: true
    };
  } else if (process.env.DB_SSL_CA && fs.existsSync(path.resolve(process.env.DB_SSL_CA))) {
    // For local development with certificate file
    sslConfig = {
      ca: fs.readFileSync(path.resolve(process.env.DB_SSL_CA)),
      rejectUnauthorized: true
    };
  } else {
    console.warn('SSL certificate not properly configured, using insecure connection');
    sslConfig = { rejectUnauthorized: false };
  }
} catch (err) {
  console.error('SSL configuration error:', err);
  sslConfig = { rejectUnauthorized: false };
}

// Database connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 4000,
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

// Test database connection
async function testDatabaseConnection() {
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.ping();
    console.log('Successfully connected to TiDB database');
    
    // Verify tables exist
    const [rows] = await connection.query(`
      SELECT COUNT(*) as table_count 
      FROM information_schema.tables 
      WHERE table_schema = ? 
      AND table_name IN ('users', 'orders')
    `, [process.env.DB_NAME]);
    
    if (rows[0].table_count !== 2) {
      console.warn('Warning: Database tables might be missing');
    }
  } catch (err) {
    console.error('Database connection failed:', err);
    if (process.env.NODE_ENV !== 'production') {
      process.exit(1);
    }
  } finally {
    if (connection) connection.release();
  }
}
testDatabaseConnection();

// Enhanced error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// JWT authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  
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

// Health check endpoint
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

// Register endpoint
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

// Login endpoint
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
      expiresIn: 3600 // 1 hour in seconds
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Failed to authenticate' });
  }
});

// Order endpoints
app.get('/orders', authenticateToken, async (req, res) => {
  try {
    // Debug: Log the user ID from the token
    console.log(`User making request:`, req.user);

    // 1. First verify the user exists
    const [users] = await pool.query('SELECT id FROM users WHERE id = ?', [req.user.id]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // 2. Fetch orders
    const [orders] = await pool.query(
      `SELECT id, order_details, created_at 
       FROM orders 
       WHERE user_id = ? 
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    // Debug: Log the raw SQL query
    console.log(`Executed query: SELECT ... WHERE user_id = ${req.user.id}`);

    res.json(orders);
  } catch (err) {
    console.error('Full error:', {
      message: err.message,
      code: err.code,
      sqlState: err.sqlState,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
    
    res.status(500).json({ 
      error: 'Database operation failed',
      ...(process.env.NODE_ENV === 'development' && { details: err.message })
    });
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

// Server startup
const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV !== 'production') {
  const server = app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  }).on('error', err => {
    console.error('Server failed to start:', err);
    process.exit(1);
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
}
// Add this endpoint to test database connectivity
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
// Export for Vercel serverless
module.exports = app;
