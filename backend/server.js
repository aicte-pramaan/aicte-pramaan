global.crypto = require('crypto');
require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const connectDB = require('./config/db');

const app = express();

// Connect Database
connectDB();

// Middleware
app.use(express.static(path.join(__dirname, '../frontend')));
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
app.get('/api/data', (req, res) => { /* ... */ });

// Endpoint to synthesize mock records for stress testing
app.get('/api/synthesize/:count', async (req, res) => {
    try {
        const startTime = Date.now();
        const count = parseInt(req.params.count) || 1000;
        
        const records = [];
        const institutions = ["INST001", "INST002", "INST003"];
        const branches = ["CSE", "IT", "ECE", "ME", "CE"];
        const firstNames = ["Aarav", "Vivaan", "Aditya", "Vihaan", "Arjun", "Sai", "Reyansh", "Ayaan", "Krishna", "Ishaan", "Ananya", "Diya", "Saanvi", "Aadhya", "Pari"];
        const lastNames = ["Sharma", "Verma", "Gupta", "Singh", "Kumar", "Patel", "Reddy", "Iyer", "Nair", "Joshi"];

        for (let i = 1; i <= count; i++) {
            const randomApaar = "1000" + String(Math.floor(10000000 + Math.random() * 90000000));
            const firstName = firstNames[Math.floor(Math.random() * firstNames.length)];
            const lastName = lastNames[Math.floor(Math.random() * lastNames.length)];
            const inst = institutions[Math.floor(Math.random() * institutions.length)];
            const branch = branches[Math.floor(Math.random() * branches.length)];
            
            records.push({
                apaar: randomApaar,
                sid: `SID-${i}`,
                name: `${firstName} ${lastName}`,
                inst: inst,
                branch: branch,
                course: `B.Tech ${branch}`,
                year: 2026,
                tfw: Math.random() < 0.05,
                ews: Math.random() < 0.10,
                nri: false,
                fn: false,
                sup: false,
                ghost_flag: Math.random() < 0.01,
                consent: true
            });
        }

        const timeTaken = ((Date.now() - startTime) / 1000).toFixed(2);
        
        res.json({
            status: "success",
            generated_count: records.length,
            time_taken_seconds: parseFloat(timeTaken),
            merkle_root: "a4f8c9213be71048e92f140938475a892b104cde3721094857342bf1092a839f",
            records: records
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
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
