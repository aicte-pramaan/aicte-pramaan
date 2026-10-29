const express = require('express');
const { authenticateToken, requireRole } = require('../middleware/authMiddleware');
const { runFuzzyMatching, runIsolationForest } = require('../utils/mlEngine');
const { createAuditEntry } = require('../utils/auditUtils');

const router = express.Router();

// Trigger Network-Wide ML Vigilance Sweep (AICTE Admin Only)
router.post('/run-ml-sweep', authenticateToken, requireRole(['AICTE']), async (req, res) => {
    try {
        const isolationResults = await runIsolationForest();
        const fuzzyMatches = await runFuzzyMatching(0.85);

        await createAuditEntry({
            actor_role: req.user.role,
            action: "ML_VIGILANCE_SWEEP",
            target_hmac: "NETWORK_WIDE",
            purpose: "Cross-Institute Duplicate & Quota Anomaly Sweep"
        });

        res.json({
            message: "Vigilance sweep complete.",
            isolation_forest: isolationResults,
            cross_institute_duplicates: fuzzyMatches
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;