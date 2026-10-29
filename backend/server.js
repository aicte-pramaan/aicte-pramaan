
global.crypto = require('crypto');
require('dotenv').config();

const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');

const connectDB = require('./config/db');
const { rehydrateMerkleTree } = require('./utils/cryptoUtils');

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Global Rate Limiter
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: {
        error: 'Too many requests, please try again later.'
    }
});

app.use(limiter);

// Serve the frontend
app.use(express.static(path.join(__dirname, '../frontend')));

// Health Check
app.get('/health', (req, res) => {
    res.json({
        status: 'Secure Node.js Core Online',
        version: '2.0.0-MERN'
    });
});

app.get('/api/data', (req, res) => {
    // Keep your existing implementation here, if any.
    res.json({ status: 'success' });
});

// Routes
app.use('/api/auth', require('./routes/authRoutes'));
app.use('/api/records', require('./routes/ingestRoutes'));
app.use('/api/audit', require('./routes/auditRoutes'));
app.use('/api/vigilance', require('./routes/vigilanceRoutes'));

// Start server only after MongoDB and the Merkle tree are ready
async function startServer() {
    await connectDB();

    // connectDB currently catches connection errors,
    // so explicitly confirm that MongoDB connected.
    if (mongoose.connection.readyState !== 1) {
        throw new Error(
            'MongoDB is not connected. Check the MONGO_URI environment variable.'
        );
    }

    console.log('MongoDB connection verified.');

    // Restore the Merkle tree from persistent database records
    await rehydrateMerkleTree();

    console.log('Merkle tree successfully restored.');

    const PORT = Number(process.env.PORT) || 5000;

    app.listen(PORT, '0.0.0.0', () => {
        console.log(
            `AICTE-PRAMAAN Server running on port ${PORT}`
        );
    });
}

startServer().catch((error) => {
    console.error('Backend startup failed:', error);
    process.exit(1);
});
