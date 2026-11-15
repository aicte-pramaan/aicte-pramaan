const express = require('express');
const Institution = require('../models/Institution');
const { authenticateToken, requireRole } = require('../middleware/authMiddleware');

const router = express.Router();

const CATEGORIES = new Set([
    'IIT', 'IISC', 'NIT', 'IIEST', 'IIIT', 'GFTI', 'RGIPT',
    'AICTE_APPROVED', 'STATE', 'OTHER', 'DEMO'
]);
const VERIFICATION_STATUSES = new Set([
    'source_listed', 'official_site_listed', 'pending_review', 'demo'
]);

function escapeRegex(value) {
    return String(value).replace(/[.*+?^${}()|[\\]\\\\]/g, '\\function escapeRegex(value) {
    return String(value).replace(/[.*+?^$()|[\]\\{}]/g, '\\$&');
}');
}

function cleanInstitution(input = {}) {
    const institution_id = String(input.institution_id || '').trim().toUpperCase();
    const name = String(input.name || '').trim();
    const category = String(input.category || 'OTHER').trim().toUpperCase();

    if (!/^[A-Z0-9][A-Z0-9._-]{1,39}$/.test(institution_id)) {
        return { error: 'institution_id must be 2–40 letters, numbers, dots, underscores or hyphens.' };
    }
    if (!name || name.length > 240) return { error: 'A valid institution name is required (max 240 characters).' };
    if (!CATEGORIES.has(category)) return { error: 'Unsupported institution category.' };

    const sourceYear = input.source_year === '' || input.source_year == null
        ? undefined
        : Number(input.source_year);
    if (sourceYear !== undefined && (!Number.isInteger(sourceYear) || sourceYear < 2000 || sourceYear > 2100)) {
        return { error: 'source_year must be a valid four-digit year.' };
    }

    const requestedStatus = String(input.verification_status || 'pending_review');
    const verification_status = VERIFICATION_STATUSES.has(requestedStatus)
        ? requestedStatus
        : 'pending_review';

    return {
        value: {
            institution_id,
            josaa_code: input.josaa_code ? String(input.josaa_code).trim() : undefined,
            name,
            short_name: String(input.short_name || '').trim(),
            category,
            state: String(input.state || '').trim(),
            city: String(input.city || '').trim(),
            website: String(input.website || '').trim(),
            aliases: Array.isArray(input.aliases)
                ? input.aliases.map(value => String(value).trim()).filter(Boolean).slice(0, 20)
                : [],
            source: String(input.source || '').trim(),
            source_url: String(input.source_url || '').trim(),
            source_year: sourceYear,
            verification_status,
            is_active: input.is_active !== false
        }
    };
}

router.get('/', async (req, res) => {
    try {
        const filter = { is_active: true };
        const q = String(req.query.q || '').trim();
        const category = String(req.query.category || '').trim().toUpperCase();
        const state = String(req.query.state || '').trim();

        if (q) {
            const expression = new RegExp(escapeRegex(q), 'i');
            filter.$or = [
                { institution_id: expression },
                { josaa_code: expression },
                { name: expression },
                { short_name: expression },
                { aliases: expression },
                { city: expression }
            ];
        }
        if (category) filter.category = category;
        if (state) filter.state = new RegExp('^' + escapeRegex(state) + '$', 'i');

        const requestedLimit = Number.parseInt(req.query.limit, 10);
        const limit = Number.isInteger(requestedLimit)
            ? Math.min(5000, Math.max(1, requestedLimit))
            : 500;
        const requestedSkip = Number.parseInt(req.query.skip, 10);
        const skip = Number.isInteger(requestedSkip) ? Math.max(0, requestedSkip) : 0;

        const [items, total] = await Promise.all([
            Institution.find(filter)
                .select('institution_id josaa_code name short_name category state city website aliases source source_url source_year verification_status is_active is_demo')
                .sort({ category: 1, state: 1, name: 1 })
                .skip(skip)
                .limit(limit)
                .lean(),
            Institution.countDocuments(filter)
        ]);

        return res.json({ status: 'success', total, count: items.length, items });
    } catch (error) {
        console.error('INSTITUTION_DIRECTORY_READ_ERROR:', error);
        return res.status(500).json({ error: 'Unable to load the institution directory.' });
    }
});

router.post('/', authenticateToken, requireRole(['AICTE']), async (req, res) => {
    try {
        const cleaned = cleanInstitution(req.body);
        if (cleaned.error) return res.status(400).json({ error: cleaned.error });

        const institution = await Institution.create({
            ...cleaned.value,
            is_demo: false
        });
        return res.status(201).json({ status: 'success', institution });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(409).json({ error: 'That institution ID or JoSAA code already exists.' });
        }
        console.error('INSTITUTION_CREATE_ERROR:', error);
        return res.status(500).json({ error: 'Unable to add the institution.' });
    }
});

router.post('/bulk-import', authenticateToken, requireRole(['AICTE']), async (req, res) => {
    try {
        const rows = req.body.institutions;
        if (!Array.isArray(rows) || rows.length === 0) {
            return res.status(400).json({ error: 'institutions[] is required.' });
        }
        if (rows.length > 2000) {
            return res.status(400).json({ error: 'Maximum 2,000 institutions per import.' });
        }

        const seen = new Set();
        const operations = [];
        let invalid = 0;
        for (const row of rows) {
            const cleaned = cleanInstitution(row);
            if (cleaned.error || seen.has(cleaned.value?.institution_id)) {
                invalid++;
                continue;
            }
            seen.add(cleaned.value.institution_id);
            operations.push({
                updateOne: {
                    filter: { institution_id: cleaned.value.institution_id },
                    update: {
                        $set: cleaned.value,
                        $setOnInsert: { is_demo: false }
                    },
                    upsert: true
                }
            });
        }

        if (operations.length === 0) {
            return res.status(400).json({ error: 'No valid institution rows were supplied.', invalid });
        }

        const result = await Institution.bulkWrite(operations, { ordered: false });
        return res.status(200).json({
            status: 'success',
            received: rows.length,
            processed: operations.length,
            invalid,
            inserted: result.upsertedCount || 0,
            updated: result.modifiedCount || 0
        });
    } catch (error) {
        console.error('INSTITUTION_BULK_IMPORT_ERROR:', error);
        return res.status(500).json({ error: 'Unable to import the institution directory.' });
    }
});

module.exports = router;
