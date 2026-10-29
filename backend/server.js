global.crypto = require('crypto');
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const connectDB = require('./config/db');

const app = express();

// Connect Database
connectDB();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Global Rate Limiter
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests, please try again later.' }
});
app.use(limiter);

// Health Check
app.get('/health', (req, res) => {
    res.json({ status: "Secure Node.js Core Online", version: "2.0.0-MERN" });
});

// Routes
app.use('/api/auth', require('./routes/authRoutes'));
app.use('/api/records', require('./routes/ingestRoutes'));
app.use('/api/audit', require('./routes/auditRoutes'));
app.use('/api/vigilance', require('./routes/vigilanceRoutes'));

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`AICTE-PRAMAAN Server running on http://127.0.0.1:${PORT}`);
});
