
const express = require('express');
const StudentRecord = require('../models/StudentRecord');

const {
    signData,
    getPublicKey,
    globalMerkleTree,
    hashLeaf,
    hashApaar
} = require('../utils/cryptoUtils');

const {
    authenticateToken,
    requireRole
} = require('../middleware/authMiddleware');

const { createAuditEntry } = require('../utils/auditUtils');

const router = express.Router();


// ============================================================
// APAAR ID NORMALIZATION
// ============================================================

function normalizeApaarId(value) {
    const raw = String(value || '').trim();
    const compact = raw.replace(/[\s-]/g, '');

    // Standard APAAR IDs contain 12 digits.
    // Preserve foreign/provisional IDs.
    return /^\d{12}$/.test(compact) ? compact : raw;
}

function parseBoolean(value, defaultValue = false) {
    if (value === undefined || value === null || value === '') {
        return defaultValue;
    }

    return value === true || value === 'true' || value === 1 || value === '1';
}

async function findRecordByApaarId(value) {
    const normalizedId = normalizeApaarId(value);

    // First check the normalized HMAC.
    let record = await StudentRecord.findOne({
        apaar_hmac: hashApaar(normalizedId)
    });

    // Backward compatibility for records previously stored
    // using the original formatted APAAR ID.
    if (!record && normalizedId !== String(value || '').trim()) {
        record = await StudentRecord.findOne({
            apaar_hmac: hashApaar(String(value).trim())
        });
    }

    return record;
}


// ============================================================
// RECENT INGESTION ACTIVITY — authenticated MongoDB ledger feed
// Returns only fields needed by the operational batch activity table.
// APAAR itself is never returned; the reference is derived from its HMAC.
// ============================================================
router.get(
    '/recent-ingestion',
    authenticateToken,
    requireRole(['AICTE', 'INSTITUTION']),
    async (req, res) => {
        try {
            const requestedLimit = Number.parseInt(req.query.limit, 10);
            const limit = Number.isInteger(requestedLimit)
                ? Math.min(100, Math.max(1, requestedLimit))
                : 40;

            // INSTITUTION tokens are scoped to their username (e.g. INST001).
            const filter = req.user.role === 'INSTITUTION'
                ? { institution_id: req.user.username }
                : {};

            const records = await StudentRecord.find(filter)
                .sort({ createdAt: -1, _id: -1 })
                .limit(limit)
                .select('apaar_hmac student_id name institution_id branch admission_year is_tfw is_ews is_nri is_fn createdAt')
                .lean();

            return res.json({
                status: 'success',
                count: records.length,
                records: records.map(record => {
                    const createdAt = record.createdAt ||
                        (record._id && typeof record._id.getTimestamp === 'function'
                            ? record._id.getTimestamp()
                            : null);
                    const quota = [];
                    if (record.is_tfw) quota.push('TFW');
                    if (record.is_ews) quota.push('EWS');
                    if (record.is_nri) quota.push('NRI');
                    if (record.is_fn) quota.push('Foreign');

                    return {
                        reference: `REC-${String(record.apaar_hmac || '').slice(-8).toUpperCase()}`,
                        student_id: record.student_id,
                        name: record.name,
                        institution_id: record.institution_id,
                        branch: record.branch,
                        admission_year: record.admission_year,
                        category: quota.length ? quota.join(' / ') : 'Regular',
                        status: 'Committed',
                        created_at: createdAt ? new Date(createdAt).toISOString() : null
                    };
                })
            });
        } catch (error) {
            console.error('RECENT_INGESTION_FEED_ERROR:', error);
            return res.status(500).json({ error: 'Unable to load recent ledger activity.' });
        }
    }
);

// ============================================================
// 1. INGEST RECORD
// ============================================================

router.post(
    '/ingest',
    authenticateToken,
    requireRole(['INSTITUTION', 'AICTE']),
    async (req, res) => {
        try {
            const {
                apaar_id,
                student_id,
                name,
                institution_id,
                branch,
                admission_year,
                is_tfw,
                is_ews,
                is_nri,
                is_fn,
                has_consent
            } = req.body;

            // Normalize and validate input.
            const normalizedApaarId = normalizeApaarId(apaar_id);

            const studentId = String(student_id || '').trim();
            const studentName = String(name || '').trim();
            const institutionId = String(institution_id || '').trim();
            const branchCode = String(branch || '').trim();
            const admissionYear = Number(admission_year);

            if (
                normalizedApaarId.length < 8 ||
                !studentId ||
                !studentName ||
                !institutionId ||
                !branchCode ||
                !Number.isInteger(admissionYear) ||
                admissionYear < 1900
            ) {
                return res.status(400).json({
                    error: 'Invalid or missing required student fields.'
                });
            }

            const apaar_hmac = hashApaar(normalizedApaarId);

            // Check for duplicate APAAR ID.
            const existing = await StudentRecord.findOne({ apaar_hmac });

            if (existing) {
                return res.status(409).json({
                    error: 'This APAAR ID is already enrolled.',
                    code: 'DUPLICATE_APAAR'
                });
            }

            // Always sign the same normalized values that are saved.
            const visiblePayload = {
                student_id: studentId,
                name: studentName,
                institution_id: institutionId,
                branch: branchCode,
                admission_year: admissionYear
            };

            const signature = signData(visiblePayload);

            // Save record to MongoDB first.
            const newRecord = new StudentRecord({
                apaar_hmac,
                student_id: studentId,
                name: studentName,
                institution_id: institutionId,
                branch: branchCode,
                admission_year: admissionYear,

                is_tfw: parseBoolean(is_tfw),
                is_ews: parseBoolean(is_ews),
                is_nri: parseBoolean(is_nri),
                is_fn: parseBoolean(is_fn),

                has_consent: parseBoolean(has_consent, true),

                ed25519_signature: signature
            });

            await newRecord.save();

            // Append the exact canonical data used by QR verification.
            const canonicalData =
                `${apaar_hmac}|${studentId}|${institutionId}|${branchCode}|${admissionYear}`;

            globalMerkleTree.appendRecord(canonicalData);

            const leafIndex = globalMerkleTree.leaves.length - 1;

            // Audit logging is handled separately so an audit failure
            // cannot make the frontend retry an already-saved record.
            let auditLogged = true;

            try {
                await createAuditEntry({
                    actor_role: req.user.role,
                    action: 'INGEST_RECORD',
                    target_hmac: apaar_hmac,
                    purpose: 'New Student Admission Enrollment'
                });
            } catch (auditError) {
                auditLogged = false;

                console.error(
                    'RECORD_SAVED_AUDIT_FAILED:',
                    auditError.message
                );
            }

            return res.status(201).json({
                status: 'success',

                message: auditLogged
                    ? 'Record cryptographically secured and audit logged.'
                    : 'Record saved, but audit logging failed. Do not submit again.',

                index: leafIndex,
                audit_logged: auditLogged,
                apaar_hmac
            });

        } catch (error) {
            console.error('INGEST_ERROR:', error);

            if (error.code === 11000) {
                return res.status(409).json({
                    error: 'This APAAR ID is already enrolled.',
                    code: 'DUPLICATE_APAAR'
                });
            }

            return res.status(500).json({
                error: 'Unable to ingest student record.'
            });
        }
    }
);


// ============================================================
// 2. GENERATE CERTIFICATE / QR PAYLOAD USING APAAR ID
// ============================================================

router.get('/generate-qr/:apaar_id', async (req, res) => {
    try {
        const record = await findRecordByApaarId(req.params.apaar_id);

        if (!record) {
            return res.status(404).json({
                error: 'Record not found in verification ledger.',
                code: 'RECORD_NOT_FOUND'
            });
        }

        if (!record.has_consent) {
            return res.status(403).json({
                error: 'Student consent has been revoked.',
                code: 'CONSENT_REVOKED'
            });
        }

        const canonicalData =
            `${record.apaar_hmac}|${record.student_id}|` +
            `${record.institution_id}|${record.branch}|${record.admission_year}`;

        const leafHash = hashLeaf(canonicalData);

        const leafIndex = globalMerkleTree.leaves.findIndex(
            leaf => leaf.equals(leafHash)
        );

        if (leafIndex === -1) {
            return res.status(500).json({
                error: 'Record exists, but Merkle tree is out of sync.',
                code: 'MERKLE_TREE_OUT_OF_SYNC'
            });
        }

        const merkleRoot = globalMerkleTree.getRoot();

        const merkleRootSignature = signData({
            merkle_root: merkleRoot
        });

        const proof = globalMerkleTree.getProof(leafIndex);

        return res.json({
            version: '1.0',

            public_key: getPublicKey(),

            apaar_hmac: record.apaar_hmac,

            data: {
                student_id: record.student_id,
                name: record.name,
                institution_id: record.institution_id,
                branch: record.branch,
                admission_year: record.admission_year
            },

            signature: record.ed25519_signature,

            merkle_root: merkleRoot,

            merkle_root_signature: merkleRootSignature,

            record_count: globalMerkleTree.leaves.length,

            proof
        });

    } catch (error) {
        console.error('QR_GENERATION_ERROR:', error);

        return res.status(500).json({
            error: 'Unable to generate verification payload.'
        });
    }
});


// ============================================================
// 3. VERIFY RECORD USING QR HMAC REFERENCE
// ============================================================

router.get('/verify-hmac/:apaar_hmac', async (req, res) => {
    try {
        const apaar_hmac = String(
            req.params.apaar_hmac || ''
        ).toLowerCase();

        if (!/^[a-f0-9]{64}$/.test(apaar_hmac)) {
            return res.status(400).json({
                error: 'Invalid verification reference.'
            });
        }

        const record = await StudentRecord.findOne({ apaar_hmac });

        if (!record) {
            return res.status(404).json({
                error: 'Record not found.',
                code: 'RECORD_NOT_FOUND'
            });
        }

        if (!record.has_consent) {
            return res.status(403).json({
                error: 'Student consent has been revoked.',
                code: 'CONSENT_REVOKED'
            });
        }

        const canonicalData =
            `${record.apaar_hmac}|${record.student_id}|` +
            `${record.institution_id}|${record.branch}|${record.admission_year}`;

        const leafHash = hashLeaf(canonicalData);

        const leafIndex = globalMerkleTree.leaves.findIndex(
            leaf => leaf.equals(leafHash)
        );

        if (leafIndex === -1) {
            return res.status(500).json({
                error: 'Merkle tree is out of sync.',
                code: 'MERKLE_TREE_OUT_OF_SYNC'
            });
        }

        const merkleRoot = globalMerkleTree.getRoot();

        const merkleRootSignature = signData({
            merkle_root: merkleRoot
        });

        const proof = globalMerkleTree.getProof(leafIndex);

        return res.json({
            version: '1.0',

            public_key: getPublicKey(),

            apaar_hmac: record.apaar_hmac,

            data: {
                student_id: record.student_id,
                name: record.name,
                institution_id: record.institution_id,
                branch: record.branch,
                admission_year: record.admission_year
            },

            signature: record.ed25519_signature,

            merkle_root: merkleRoot,

            merkle_root_signature: merkleRootSignature,

            record_count: globalMerkleTree.leaves.length,

            proof
        });

    } catch (error) {
        console.error('HMAC_VERIFICATION_ERROR:', error);

        return res.status(500).json({
            error: 'Unable to verify this record.'
        });
    }
});


// ============================================================
// 4. STUDENT CONSENT REVOCATION
// ============================================================

router.post('/student/revoke-consent', async (req, res) => {
    try {
        const { apaar_id } = req.body;

        if (!apaar_id) {
            return res.status(400).json({
                error: 'APAAR ID is required.'
            });
        }

        const record = await findRecordByApaarId(apaar_id);

        if (!record) {
            return res.status(404).json({
                error: 'Record not found.'
            });
        }

        record.has_consent = false;

        await record.save();

        await createAuditEntry({
            actor_role: 'STUDENT',
            action: 'REVOKE_CONSENT',
            target_hmac: record.apaar_hmac,
            purpose: 'DPDP Act Privacy Revocation'
        });

        return res.json({
            status: 'Revoked',
            message: 'Consent revoked. External verification blocked.'
        });

    } catch (error) {
        console.error('CONSENT_REVOCATION_ERROR:', error);

        return res.status(500).json({
            error: 'Unable to process consent revocation.'
        });
    }
});

// ============================================================
// BULK INGEST (registry → ledger sync)
// ============================================================
router.post(
    '/bulk-ingest',
    authenticateToken,
    requireRole(['AICTE']),
    async (req, res) => {
        try {
            const items = req.body.records;

            if (!Array.isArray(items) || items.length === 0) {
                return res.status(400).json({ error: 'records[] is required.' });
            }
            if (items.length > 2000) {
                return res.status(400).json({ error: 'Max 2000 records per request.' });
            }

            let invalid = 0, duplicateInBatch = 0;
            const prepared = new Map();

            for (const r of items) {
                const apaarId = normalizeApaarId(r.apaar_id);
                const studentId = String(r.student_id || '').trim();
                const name = String(r.name || '').trim();
                const institutionId = String(r.institution_id || '').trim();
                const branch = String(r.branch || '').trim();
                const year = Number(r.admission_year);

                if (
                    apaarId.length < 8 || !studentId || !name ||
                    !institutionId || !branch ||
                    !Number.isInteger(year) || year < 1900
                ) { invalid++; continue; }

                const apaar_hmac = hashApaar(apaarId);
                if (prepared.has(apaar_hmac)) { duplicateInBatch++; continue; }

                const visiblePayload = {
                    student_id: studentId,
                    name,
                    institution_id: institutionId,
                    branch,
                    admission_year: year
                };

                prepared.set(apaar_hmac, {
                    apaar_hmac,
                    ...visiblePayload,
                    is_tfw: parseBoolean(r.is_tfw),
                    is_ews: parseBoolean(r.is_ews),
                    is_nri: parseBoolean(r.is_nri),
                    is_fn: parseBoolean(r.is_fn),
                    has_consent: parseBoolean(r.has_consent, true),
                    ed25519_signature: signData(visiblePayload)
                });
            }

            // Skip records that are already in the ledger.
            const existing = await StudentRecord
                .find({ apaar_hmac: { $in: [...prepared.keys()] } })
                .select('apaar_hmac')
                .lean();
            const existingSet = new Set(existing.map(e => e.apaar_hmac));

            const docs = [];
            for (const [h, doc] of prepared) {
                if (!existingSet.has(h)) docs.push(doc);
            }

            let inserted = [];
            if (docs.length) {
                try {
                    inserted = await StudentRecord.insertMany(docs, { ordered: false });
                } catch (err) {
                    // Partial success (e.g. race on a unique index)
                    if (Array.isArray(err.insertedDocs)) inserted = err.insertedDocs;
                    else throw err;
                }
            }

            for (const rec of inserted) {
                globalMerkleTree.appendRecord(
                    `${rec.apaar_hmac}|${rec.student_id}|${rec.institution_id}|${rec.branch}|${rec.admission_year}`
                );
            }

            try {
                await createAuditEntry({
                    actor_role: req.user.role,
                    action: 'BULK_INGEST',
                    target_hmac: `BULK_${inserted.length}`,
                    purpose: 'Registry to ledger synchronisation'
                });
            } catch (e) {
                console.error('BULK_AUDIT_FAILED:', e.message);
            }

            return res.status(201).json({
                status: 'success',
                inserted: inserted.length,
                already_present: existingSet.size,
                duplicate_in_batch: duplicateInBatch,
                invalid,
                record_count: globalMerkleTree.leaves.length
            });
        } catch (error) {
            console.error('BULK_INGEST_ERROR:', error);
            return res.status(500).json({ error: 'Unable to bulk ingest records.' });
        }
    }
);

// ============================================================
// EXPORT ROUTER
// ============================================================

module.exports = router;
