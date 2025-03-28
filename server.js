console.log('Starting server with environment:', {
  NODE_ENV: process.env.NODE_ENV,
  PORT: process.env.PORT,
  DB_HOST: process.env.DB_HOST ? 'set' : 'missing',
  JWT_SECRET: process.env.JWT_SECRET ? 'set' : 'missing'
});

const fs = require('fs'); // Add this at the top of your backend file
require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors()); // Enable CORS for all routes

// Or with more specific configuration
app.use(cors({
    origin: ["http://localhost:5173"],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}))

//app.use(cors({
  //origin: [
    //"http://localhost:5173", 
    //"https://your-frontend-domain.com"
  //],
  //methods: ['GET', 'POST', 'PUT', 'DELETE'],
  //credentials: true
//}))

// MySQL connection
//const db = mysql.createConnection({
    //host: 'localhost',
    //user: 'root', // Replace with your MySQL username
    //password: '', // Replace with your MySQL password
    //database: 'orderapp'
//});

// MySQL connection using environment variables
//const db = mysql.createConnection({
    //host: process.env.DB_HOST,
    //user: process.env.DB_USER,
    //password: process.env.DB_PASSWORD,
    //database: process.env.DB_NAME
//});

//const db = mysql.createConnection({
    //host: process.env.DB_HOST,
    //port: process.env.DB_PORT, // Add this line
    //user: process.env.DB_USER,
    //password: process.env.DB_PASSWORD,
    //database: process.env.DB_NAME,
    //ssl: {
      //ca: fs.readFileSync(process.env.DB_SSL_CA) // For SSL certificate
      // OR if using standard certs:
      // rejectUnauthorized: true
    }
  });

// Remove ALL other db connection code and keep ONLY this:
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: process.env.DB_SSL === 'true' ? { 
    rejectUnauthorized: false
  } : null
});

// Test connection
db.getConnection((err, connection) => {
  if (err) {
    console.error('Database connection failed:', err);
    // Don't exit in production - let the server try to reconnect
    if (process.env.NODE_ENV !== 'production') process.exit(1);
  } else {
    console.log('Database connected');
    connection.release();
  }
});


// Test connection
db.getConnection((err, connection) => {
  if (err) {
    console.error('Database connection failed:', err);
    process.exit(1);
  }
  console.log('Database connected');
  connection.release();
});


// Connect to MySQL
db.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL database');
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Server Error');
});

// Middleware to verify JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, 'your_secret_key', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Register endpoint
app.post('/register', (req, res) => {
    const { username, password } = req.body;

    // Check if the username already exists
    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            return res.status(400).send('Username already exists');
        }

        // Hash the password
        const hashedPassword = bcrypt.hashSync(password, 10);

        // Insert the new user into the database
        db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, results) => {
            if (err) throw err;
            res.status(201).send('User registered successfully');
        });
    });
});

// Login endpoint
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Fetch user from the database
    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) throw err;
        if (results.length === 0) return res.status(400).send('User not found');

        const user = results[0];

        // Compare the provided password with the stored hash
        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(400).send('Invalid password');
        }

        // Generate a JWT token
        const token = jwt.sign({ id: user.id }, 'your_secret_key', { expiresIn: '1h' });
        res.json({ token });
    });
});

// Fetch orders endpoint
app.get('/orders', authenticateToken, (req, res) => {
    const userId = req.user.id;

    // Fetch orders for the logged-in user
    db.query('SELECT * FROM orders WHERE user_id = ?', [userId], (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

// Create order endpoint
app.post('/orders', authenticateToken, (req, res) => {
    const { order_details } = req.body;
    const userId = req.user.id;

    // Insert the new order into the database
    db.query('INSERT INTO orders (user_id, order_details) VALUES (?, ?)', [userId, order_details], (err, results) => {
        if (err) throw err;
        res.json({ id: results.insertId, user_id: userId, order_details });
    });
});

// Update order endpoint
app.put('/orders/:id', authenticateToken, (req, res) => {
    const { order_details } = req.body;
    const orderId = req.params.id;
    const userId = req.user.id;

    // Update the order in the database
    db.query('UPDATE orders SET order_details = ? WHERE id = ? AND user_id = ?', [order_details, orderId, userId], (err, results) => {
        if (err) throw err;
        if (results.affectedRows === 0) return res.status(404).send('Order not found');
        res.json({ id: orderId, user_id: userId, order_details });
    });
});

// Delete order endpoint
app.delete('/orders/:id', authenticateToken, (req, res) => {
    const orderId = req.params.id;
    const userId = req.user.id;

    // Delete the order from the database
    db.query('DELETE FROM orders WHERE id = ? AND user_id = ?', [orderId, userId], (err, results) => {
        if (err) throw err;
        if (results.affectedRows === 0) return res.status(404).send('Order not found');
        res.sendStatus(204);
    });
});

// Start the server
//const PORT = 3000;
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
