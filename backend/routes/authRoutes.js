const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const router = express.Router();

// Mock Users Database
const MOCK_USERS = {
    "INST001": {
        passwordHash: bcrypt.hashSync("password123", 10),
        role: "INSTITUTION",
        requires2FA: true
    },
    "EMP001": {
        passwordHash: bcrypt.hashSync("password123", 10),
        role: "EMPLOYER",
        requires2FA: false
    },
    "AICTE_ADMIN": {
        passwordHash: bcrypt.hashSync("admin123", 10),
        role: "AICTE",
        requires2FA: true
    }
};

// Login Route
router.post('/login', async (req, res) => {
    try {
        const { username, password, totp_code } = req.body;
        const user = MOCK_USERS[username];

        if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // Handle 2FA Verification
        if (user.requires2FA) {
            const demoCode = "123456";
            console.log(`\n--- DEMO 2FA CODE for ${username}: ${demoCode} ---\n`);

            if (!totp_code || totp_code !== demoCode) {
                return res.status(401).json({ 
                    error: 'Invalid or missing 2FA code. Please provide 123456' 
                });
            }
        }

        // Sign JWT Access Token
        const token = jwt.sign(
            { username, role: user.role },
            process.env.JWT_SECRET || 'super_secure_jwt_secret_for_aicte_2026',
            { expiresIn: '1h' }
        );

        res.json({ access_token: token, token_type: 'Bearer', role: user.role });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;