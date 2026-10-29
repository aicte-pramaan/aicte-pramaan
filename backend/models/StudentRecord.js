const mongoose = require('mongoose');

const studentRecordSchema = new mongoose.Schema({
    apaar_hmac: { type: String, required: true, unique: true },
    student_id: { type: String, required: true },
    name: { type: String, required: true },
    institution_id: { type: String, required: true },
    branch: { type: String, required: true },
    admission_year: { type: Number, required: true },
    is_tfw: { type: Boolean, default: false },
    is_ews: { type: Boolean, default: false },
    is_nri: { type: Boolean, default: false },
    is_fn: { type: Boolean, default: false },
    ghost_flag: { type: Boolean, default: false },
    has_consent: { type: Boolean, default: true },
    ed25519_signature: { type: String, required: true }
}, { timestamps: true });

module.exports = mongoose.model('StudentRecord', studentRecordSchema);
