const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
    actor_role: { type: String, required: true },
    action: { type: String, required: true },
    target_hmac: { type: String, required: true },
    purpose: { type: String, required: true },
    prev_hash: { type: String, required: true },
    block_hash: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
}, { timestamps: true });

module.exports = mongoose.model('AuditLog', auditLogSchema);