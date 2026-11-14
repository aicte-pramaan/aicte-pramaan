const mongoose = require('mongoose');

const institutionSchema = new mongoose.Schema({
    institution_id: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        uppercase: true,
        maxlength: 40
    },
    josaa_code: { type: String, trim: true, index: true },
    name: { type: String, required: true, trim: true, maxlength: 240 },
    short_name: { type: String, trim: true, maxlength: 80 },
    category: {
        type: String,
        required: true,
        uppercase: true,
        enum: ['IIT', 'IISC', 'NIT', 'IIEST', 'IIIT', 'GFTI', 'RGIPT', 'AICTE_APPROVED', 'STATE', 'OTHER', 'DEMO']
    },
    state: { type: String, trim: true, maxlength: 100 },
    city: { type: String, trim: true, maxlength: 120 },
    website: { type: String, trim: true, maxlength: 300 },
    aliases: [{ type: String, trim: true }],
    source: { type: String, trim: true, maxlength: 160 },
    source_url: { type: String, trim: true, maxlength: 500 },
    source_year: { type: Number, min: 2000, max: 2100 },
    verification_status: {
        type: String,
        enum: ['source_listed', 'official_site_listed', 'pending_review', 'demo'],
        default: 'pending_review'
    },
    is_active: { type: Boolean, default: true },
    is_demo: { type: Boolean, default: false }
}, { timestamps: true });

institutionSchema.index({ category: 1, state: 1, name: 1 });
institutionSchema.index({ name: 'text', aliases: 'text' });

module.exports = mongoose.model('Institution', institutionSchema);
