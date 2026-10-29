const crypto = require('crypto');
const AuditLog = require('../models/AuditLog');

const createAuditEntry = async ({ actor_role, action, target_hmac, purpose }) => {
    try {
        const lastLog = await AuditLog.findOne().sort({ createdAt: -1 });
        const prev_hash = lastLog ? lastLog.block_hash : "GENESIS_BLOCK_HASH_AICTE_PRAMAAN";

        const timestamp = new Date().toISOString();

        const block_hash = crypto.createHash('sha256')
            .update(`${prev_hash}|${actor_role}|${action}|${target_hmac}|${timestamp}`)
            .digest('hex');

        const logEntry = new AuditLog({
            actor_role,
            action,
            target_hmac,
            purpose,
            prev_hash,
            block_hash,
            timestamp
        });

        await logEntry.save();
        return logEntry;
    } catch (error) {
        console.error("Audit log creation error:", error.message);
        throw error;
    }
};

module.exports = { createAuditEntry };
