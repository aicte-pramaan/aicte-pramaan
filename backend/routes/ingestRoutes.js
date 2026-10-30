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


// 1. INGEST RECORD
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

            // Validate required fields
            if (
                !apaar_id ||
                !student_id ||
                !name ||
                !institution_id ||
                !branch ||
                !admission_year
            ) {
                return res.status(400).json({
                    error: 'Missing required fields.'
                });
            }

            // Generate HMAC reference
            const apaar_hmac = hashApaar(apaar_id);

            // Check for duplicate student
            const existing = await StudentRecord.findOne({ apaar_hmac });

            if (existing) {
                return res.status(400).json({
                    error: 'Student already enrolled.'
                });
            }

            // Sign visible payload
            const visiblePayload = {
                student_id,
                name,
                institution_id,
                branch,
                admission_year
            };

            const signature = signData(visiblePayload);

            // Save record to MongoDB
            const newRecord = new StudentRecord({
                apaar_hmac,
                student_id,
                name,
                institution_id,
                branch,
                admission_year,

                is_tfw: is_tfw === true || is_tfw === 'true',
                is_ews: is_ews === true || is_ews === 'true',
                is_nri: is_nri === true || is_nri === 'true',
                is_fn: is_fn === true || is_fn === 'true',

                has_consent: has_consent === undefined
                    ? true
                    : (has_consent === true || has_consent === 'true'),

                ed25519_signature: signature
            });

            await newRecord.save();

            // Append to Merkle Tree only after MongoDB save succeeds
            const canonicalData =
                `${apaar_hmac}|${student_id}|${institution_id}|${branch}|${admission_year}`;

            globalMerkleTree.appendRecord(canonicalData);

            const leafIndex = globalMerkleTree.leaves.length - 1;

            // Create audit log
            let auditLogged = true;

            try {
                await createAuditEntry({
                    actor_role: req.user.role,
                    action: "INGEST_RECORD",
                    target_hmac: apaar_hmac,
                    purpose: "New Student Admission Enrollment"
                });
            } catch (auditError) {
                auditLogged = false;

                console.error(
                    "RECORD_SAVED_AUDIT_FAILED:",
                    auditError.message
                );
            }

            // Return successful record creation response
            return res.status(201).json({
                status: "success",

                message: auditLogged
                    ? "Record cryptographically secured and audit logged."
                    : "Record saved, but audit logging failed. Do not submit this record again.",

                index: leafIndex,
                audit_logged: auditLogged
            });

        } catch (error) {
            console.error("INGEST_ERROR:", error);

            return res.status(500).json({
                error: error.message,
                stack: error.stack
            });
        }
    }
);


// 2. GENERATE OFFLINE QR PAYLOAD
router.get('/generate-qr/:apaar_id', async (req, res) => {
    try {
        const apaar_hmac = hashApaar(req.params.apaar_id);

        const record = await StudentRecord.findOne({ apaar_hmac });

        if (!record) {
            return res.status(404).json({
                error: "Record not found"
            });
        }

        if (!record.has_consent) {
            return res.status(403).json({
                error: "Student revoked DPDP consent for verification."
            });
        }

        const canonicalData =
            `${record.apaar_hmac}|${record.student_id}|${record.institution_id}|${record.branch}|${record.admission_year}`;

        const leafHash = hashLeaf(canonicalData);

        const leafIndex = globalMerkleTree.leaves.findIndex(
            leaf => leaf.equals(leafHash)
        );

        if (leafIndex === -1) {
            return res.status(500).json({
                error: "Tree out of sync. Restart server and ingest fresh."
            });
        }

        // Calculate current Merkle root
        const merkleRoot = globalMerkleTree.getRoot();

        // Sign Merkle root
        const merkleRootSignature = signData({
            merkle_root: merkleRoot
        });

        // Generate inclusion proof
        const proof = globalMerkleTree.getProof(leafIndex);

        const payload = {
            version: "1.0",

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

            proof: proof
        };

        return res.json(payload);

    } catch (error) {
        console.error("QR generation error:", error);

        return res.status(500).json({
            error: error.message,
            stack: error.stack
        });
    }
});


// 3. VERIFY RECORD USING APAAR HMAC
router.get('/verify-hmac/:apaar_hmac', async (req, res) => {
    try {
        const apaar_hmac = String(
            req.params.apaar_hmac || ""
        ).toLowerCase();

        if (!/^[a-f0-9]{64}$/.test(apaar_hmac)) {
            return res.status(400).json({
                error: "Invalid verification reference"
            });
        }

        const record = await StudentRecord.findOne({ apaar_hmac });

        if (!record) {
            return res.status(404).json({
                error: "Record not found"
            });
        }

        if (!record.has_consent) {
            return res.status(403).json({
                error: "Student consent has been revoked"
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
                error: "Merkle tree is out of sync"
            });
        }

        const merkleRoot = globalMerkleTree.getRoot();

        const merkleRootSignature = signData({
            merkle_root: merkleRoot
        });

        const proof = globalMerkleTree.getProof(leafIndex);

        return res.json({
            version: "1.0",

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
        console.error("HMAC verification error:", error);

        return res.status(500).json({
            error: "Unable to verify this record"
        });
    }
});


// 4. STUDENT CONSENT REVOCATION
router.post('/student/revoke-consent', async (req, res) => {
    try {
        const { apaar_id } = req.body;

        const apaar_hmac = hashApaar(apaar_id);

        const record = await StudentRecord.findOne({ apaar_hmac });

        if (!record) {
            return res.status(404).json({
                error: "Record not found"
            });
        }

        record.has_consent = false;

        await record.save();

        await createAuditEntry({
            actor_role: "STUDENT",
            action: "REVOKE_CONSENT",
            target_hmac: apaar_hmac,
            purpose: "DPDP Act Privacy Revocation"
        });

        return res.json({
            status: "Revoked",
            message: "DPDP Act enforced. Third-party access blocked."
        });

    } catch (error) {
        console.error("CONSENT_REVOCATION_ERROR:", error);

        return res.status(500).json({
            error: error.message,
            stack: error.stack
        });
    }
});


// Export router
module.exports = router;