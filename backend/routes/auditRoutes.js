const express = require('express');
const AuditLog = require('../models/AuditLog');
const { authenticateToken, requireRole } = require('../middleware/authMiddleware');

const router = express.Router();

// Fetch Audit Chain & Verify Integrity
router.get('/verify-chain', authenticateToken, requireRole(['AICTE', 'EMPLOYER']), async (req, res) => {
    try {
        const logs = await AuditLog.find().sort({ createdAt: 1 });
        let isChainValid = true;
        const brokenBlocks = [];

        for (let i = 1; i < logs.length; i++) {
            const current = logs[i];
            const previous = logs[i - 1];

            if (current.prev_hash !== previous.block_hash) {
                isChainValid = false;
                brokenBlocks.push({ index: i, logId: current._id });
            }
        }

        res.json({
            chain_length: logs.length,
            is_valid: isChainValid,
            broken_blocks: brokenBlocks,
            logs
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;