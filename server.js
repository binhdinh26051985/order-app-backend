const fs = require('fs');
const path = require('path');
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS Configuration
const allowedOrigins = [
  'http://localhost:5173',
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true
}));

// Database Connection Pool
let dbPool;

const initializeDatabase = async () => {
  try {
    let sslOptions = null;
    
    // Handle SSL for different environments
    if (process.env.DB_SSL_CA) {
      if (process.env.DB_SSL_CA.includes('BEGIN CERTIFICATE')) {
        // Direct PEM content from env variable
        sslOptions = { ca: process.env.DB_SSL_CA };
      } else if (fs.existsSync(path.resolve(process.env.DB_SSL_CA))) {
        // File path provided
        sslOptions = { ca: fs.readFileSync(path.resolve(process.env.DB_SSL_CA)) };
      }
    } else if (process.env.NODE_ENV === 'production') {
      // Default SSL for production
      sslOptions = { rejectUnauthorized: true };
    }

    dbPool = mysql.createPool({
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
    const conn = await dbPool.getConnection();
    await conn.ping();
    conn.release();
    console.log('✅ Database connected successfully');
  } catch (err) {
    console.error('❌ Database connection failed:', err);
    // Retry logic for production
    if (process.env.NODE_ENV === 'production') {
      setTimeout(initializeDatabase, 5000); // Retry after 5 seconds
    }
  }
};

// Initialize database immediately
initializeDatabase();

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret-123', (err, user) => {
    if (err) return res.status(403).json({ error: 'Forbidden' });
    req.user = user;
    next();
  });
};

// Health Check Endpoint
app.get('/health', async (req, res) => {
  try {
    if (!dbPool) throw new Error('Database not initialized');
    const [rows] = await dbPool.query('SELECT 1 + 1 AS result');
    res.json({
      status: 'OK',
      database: 'connected',
      result: rows[0].result,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({
      status: 'Unhealthy',
      error: err.message,
      database: dbPool ? 'connected' : 'disconnected'
    });
  }
});

// User Registration
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Check if user exists
    const [users] = await dbPool.execute(
      'SELECT id FROM users WHERE username = ?', 
      [username]
    );
    
    if (users.length > 0) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    // Hash password and create user
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await dbPool.execute(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword]
    );

    res.status(201).json({ 
      message: 'User registered successfully',
      userId: result.insertId 
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User Login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Find user
    const [users] = await dbPool.execute(
      'SELECT id, username, password FROM users WHERE username = ?',
      [username]
    );
    
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create JWT token
    const token = jwt.sign(
      { 
        id: user.id, 
        username: user.username 
      },
      process.env.JWT_SECRET || 'fallback-secret-123',
      { expiresIn: '1h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected Order Endpoints
app.get('/orders', authenticateToken, async (req, res) => {
  try {
    const [orders] = await dbPool.execute(
      'SELECT * FROM orders WHERE user_id = ?',
      [req.user.id]
    );
    res.json(orders);
  } catch (err) {
    console.error('Get orders error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
// PUT (Edit) Order Endpoint
app.put('/orders/:id', authenticateToken, async (req, res) => {
  try {
    const orderId = req.params.id;
    const userId = req.user.id;
    const { order_details } = req.body;

    if (!order_details) {
      return res.status(400).json({ error: 'Order details are required' });
    }

    // Check ownership
    const [existing] = await dbPool.execute(
      'SELECT id FROM orders WHERE id = ? AND user_id = ?',
      [orderId, userId]
    );

    if (existing.length === 0) {
      return res.status(404).json({ error: 'Order not found or access denied' });
    }

    // Update without updated_at
    await dbPool.execute(
      'UPDATE orders SET order_details = ? WHERE id = ?',
      [order_details, orderId]
    );

    // Return updated order
    const [updatedOrder] = await dbPool.execute(
      'SELECT * FROM orders WHERE id = ?',
      [orderId]
    );

    res.json(updatedOrder[0]);
  } catch (err) {
    console.error('Update error:', err);
    res.status(500).json({ 
      error: 'Failed to update order',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// DELETE Order Endpoint
app.delete('/orders/:id', authenticateToken, async (req, res) => {
  try {
    const orderId = req.params.id;
    const userId = req.user.id;

    // Check if order exists and belongs to user
    const [existing] = await dbPool.execute(
      'SELECT id FROM orders WHERE id = ? AND user_id = ?',
      [orderId, userId]
    );

    if (existing.length === 0) {
      return res.status(404).json({ error: 'Order not found or access denied' });
    }

    // Delete the order
    const [result] = await dbPool.execute(
      'DELETE FROM orders WHERE id = ?',
      [orderId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    res.status(204).end(); // No content response for successful deletion
  } catch (err) {
    console.error('Delete order error:', err);
    res.status(500).json({ 
      error: 'Failed to delete order',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});


app.post('/orders', authenticateToken, async (req, res) => {
  try {
    const { order_details } = req.body;
    
    if (!order_details) {
      return res.status(400).json({ error: 'Order details are required' });
    }

    const [result] = await dbPool.execute(
      'INSERT INTO orders (user_id, order_details) VALUES (?, ?)',
      [req.user.id, order_details]
    );

    res.status(201).json({
      id: result.insertId,
      user_id: req.user.id,
      order_details
    });
  } catch (err) {
    console.error('Create order error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    ...(process.env.NODE_ENV !== 'production' && { details: err.message })
  });
});

// Export for Vercel
module.exports = app;

// Local server (only for development)
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}
