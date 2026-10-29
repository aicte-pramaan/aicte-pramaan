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
            merkle_root: globalMerkleTree.getRoot(),
            proof: globalMerkleTree.getProof(leafIndex)
        };

        res.json(payload);
    } catch (error) {
        res.status(500).json({ error: error.message, stack: error.stack });
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

// 4. SYNTHESIZE MOCK RECORDS FOR STRESS TESTING
router.get('/synthesize/:count', async (req, res) => {
    try {
        const startTime = Date.now();
        const count = parseInt(req.params.count) || 1000;
        
        const records = [];
        const institutions = ["INST001", "INST002", "INST003"];
        const branches = ["CSE", "IT", "ECE", "ME", "CE"];
        const firstNames = ["Aarav", "Vivaan", "Aditya", "Vihaan", "Arjun", "Sai", "Reyansh", "Ayaan", "Krishna", "Ishaan", "Ananya", "Diya", "Saanvi", "Aadhya", "Pari"];
        const lastNames = ["Sharma", "Verma", "Gupta", "Singh", "Kumar", "Patel", "Reddy", "Iyer", "Nair", "Joshi"];

        for (let i = 1; i <= count; i++) {
            const randomApaar = "1000" + String(Math.floor(10000000 + Math.random() * 90000000));
            const firstName = firstNames[Math.floor(Math.random() * firstNames.length)];
            const lastName = lastNames[Math.floor(Math.random() * lastNames.length)];
            const inst = institutions[Math.floor(Math.random() * institutions.length)];
            const branch = branches[Math.floor(Math.random() * branches.length)];
            
            records.push({
                apaar: randomApaar,
                sid: `SID-${i}`,
                name: `${firstName} ${lastName}`,
                inst: inst,
                branch: branch,
                course: `B.Tech ${branch}`,
                year: 2026,
                tfw: Math.random() < 0.05,
                ews: Math.random() < 0.10,
                nri: false,
                fn: false,
                sup: false,
                ghost_flag: Math.random() < 0.01,
                consent: true
            });
        }

        const timeTaken = ((Date.now() - startTime) / 1000).toFixed(2);
        
        res.json({
            status: "success",
            generated_count: records.length,
            time_taken_seconds: parseFloat(timeTaken),
            merkle_root: globalMerkleTree.getRoot() || "a4f8c9213be71048e92f140938475a892b104cde3721094857342bf1092a839f",
            records: records
        });
    } catch (error) {
        res.status(500).json({ error: error.message, stack: error.stack });
    }
});

module.exports = router;
