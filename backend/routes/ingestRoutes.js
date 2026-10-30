const express = require('express');
const crypto = require('crypto');
const StudentRecord = require('../models/StudentRecord');
const { signData, getPublicKey, globalMerkleTree, hashLeaf, hashApaar } = require('../utils/cryptoUtils');
const { authenticateToken, requireRole } = require('../middleware/authMiddleware');
const { createAuditEntry } = require('../utils/auditUtils');

const router = express.Router();

// 1. INGEST RECORD
router.post('/ingest', authenticateToken, requireRole(['INSTITUTION', 'AICTE']), async (req, res) => {
    try {
        const { apaar_id, student_id, name, institution_id, branch, admission_year, is_tfw, has_consent } = req.body;

        if (!apaar_id || !student_id || !name || !institution_id || !branch || !admission_year) {
            return res.status(400).json({ error: 'Missing required fields.' });
        }

        const apaar_hmac = hashApaar(apaar_id);

        const existing = await StudentRecord.findOne({ apaar_hmac });
        if (existing) {
            return res.status(400).json({ error: 'Student already enrolled.' });
        }

        // Append to Merkle Tree
        const canonicalData = `${apaar_hmac}|${student_id}|${institution_id}|${branch}|${admission_year}`;
        globalMerkleTree.appendRecord(canonicalData);
        const leafIndex = globalMerkleTree.leaves.length - 1;

        // Sign visible payload
        const visiblePayload = { student_id, name, institution_id, branch, admission_year };
        const signature = signData(visiblePayload);

        // Save to MongoDB
        const newRecord = new StudentRecord({
            apaar_hmac,
            student_id,
            name,
            institution_id,
            branch,
            admission_year,
            is_tfw: is_tfw || false,
            has_consent: has_consent !== undefined ? has_consent : true,
            ed25519_signature: signature
        });
        await newRecord.save();

        // Audit Log
        await createAuditEntry({
            actor_role: req.user.role,
            action: "INGEST_RECORD",
            target_hmac: apaar_hmac,
            purpose: "New Student Admission Enrollment"
        });

        res.json({ status: "success", message: "Cryptographically secured", index: leafIndex });
    } catch (error) {
        console.error("INGEST_ERROR:", error);
        res.status(500).json({ error: error.message, stack: error.stack });
    }
});

// 2. GENERATE OFFLINE QR PAYLOAD
router.get('/generate-qr/:apaar_id', async (req, res) => {
    try {
        const apaar_hmac = hashApaar(req.params.apaar_id);
        const record = await StudentRecord.findOne({ apaar_hmac });

        if (!record) return res.status(404).json({ error: "Record not found" });
        if (!record.has_consent) return res.status(403).json({ error: "Student revoked DPDP consent for verification." });

        const canonicalData = `${record.apaar_hmac}|${record.student_id}|${record.institution_id}|${record.branch}|${record.admission_year}`;

        const leafHash = hashLeaf(canonicalData);
        const leafIndex = globalMerkleTree.leaves.findIndex(leaf => leaf.equals(leafHash));

        if (leafIndex === -1) {
            return res.status(500).json({ error: "Tree out of sync. Restart server and ingest fresh." });
        }





        // Calculate the CURRENT Merkle root for the restored tree.
        const merkleRoot = globalMerkleTree.getRoot();

        // Sign the current root using the persistent Ed25519 key.
        const merkleRootSignature = signData({
            merkle_root: merkleRoot
        });

        // Generate the inclusion proof from the same current tree.
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
        res.status(500).json({ error: error.message, stack: error.stack });
    }
});

// Verify a record using its opaque APAAR HMAC reference.
router.get('/verify-hmac/:apaar_hmac', async (req, res) => {
    try {
        const apaar_hmac = String(req.params.apaar_hmac || "").toLowerCase();

        if (!/^[a-f0-9]{64}$/.test(apaar_hmac)) {
            return res.status(400).json({ error: "Invalid verification reference" });
        }

        const record = await StudentRecord.findOne({ apaar_hmac });

        if (!record) {
            return res.status(404).json({ error: "Record not found" });
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

// 3. STUDENT CONSENT REVOCATION
router.post('/student/revoke-consent', async (req, res) => {
    try {
        const { apaar_id } = req.body;
        const apaar_hmac = hashApaar(apaar_id);

        const record = await StudentRecord.findOne({ apaar_hmac });
        if (!record) return res.status(404).json({ error: "Record not found" });

        record.has_consent = false;
        await record.save();

        await createAuditEntry({
            actor_role: "STUDENT",
            action: "REVOKE_CONSENT",
            target_hmac: apaar_hmac,
            purpose: "DPDP Act Privacy Revocation"
        });

        res.json({ status: "Revoked", message: "DPDP Act enforced. Third-party access blocked." });
    } catch (error) {
        res.status(500).json({ error: error.message, stack: error.stack });
    }
});

module.exports = router;
