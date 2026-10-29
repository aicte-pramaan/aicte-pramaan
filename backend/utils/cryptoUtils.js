const crypto = require('crypto');
const nacl = require('tweetnacl');

const keyPair = nacl.sign.keyPair();

const getPublicKey = () => Buffer.from(keyPair.publicKey).toString('hex');

const signData = (data) => {
    const dataBytes = new TextEncoder().encode(JSON.stringify(data));
    const signature = nacl.sign.detached(dataBytes, keyPair.secretKey);
    return Buffer.from(signature).toString('hex');
};

const hashLeaf = (data) => {
    const prefix = Buffer.from([0x00]);
    return crypto.createHash('sha256')
        .update(Buffer.concat([prefix, Buffer.from(data)]))
        .digest();
};

const hashPair = (left, right) => {
    const prefix = Buffer.from([0x01]);
    return crypto.createHash('sha256')
        .update(Buffer.concat([prefix, left, right]))
        .digest();
};

class MerkleTree {
    constructor() {
        this.leaves = [];
    }

    appendRecord(data) {
        const leaf = hashLeaf(data);
        this.leaves.push(leaf);
    }

    getRoot() {
        if (this.leaves.length === 0) return "";
        let level = [...this.leaves];
        while (level.length > 1) {
            const nextLevel = [];
            for (let i = 0; i < level.length; i += 2) {
                if (i + 1 < level.length) {
                    nextLevel.push(hashPair(level[i], level[i + 1]));
                } else {
                    nextLevel.push(level[i]);
                }
            }
            level = nextLevel;
        }
        return level[0].toString('hex');
    }

    getProof(index) {
        if (index < 0 || index >= this.leaves.length) return [];
        const proof = [];
        let level = [...this.leaves];
        let idx = index;

        while (level.length > 1) {
            const nextLevel = [];
            for (let i = 0; i < level.length; i += 2) {
                if (i + 1 < level.length) {
                    if (i === idx) {
                        proof.push({ position: 'right', sibling: level[i + 1].toString('hex') });
                    } else if (i + 1 === idx) {
                        proof.push({ position: 'left', sibling: level[i].toString('hex') });
                    }
                    nextLevel.push(hashPair(level[i], level[i + 1]));
                } else {
                    nextLevel.push(level[i]);
                }
            }
            idx = Math.floor(idx / 2);
            level = nextLevel;
        }
        return proof;
    }
}

const globalMerkleTree = new MerkleTree();

const hashApaar = (apaar_id) => {
    return crypto.createHmac('sha256', process.env.HMAC_SECRET || 'aicte_super_secret_hmac_key_2026')
                 .update(apaar_id)
                 .digest('hex');
};

const rehydrateMerkleTree = async () => {
    const StudentRecord = require('../models/StudentRecord');
    globalMerkleTree.leaves = [];
    const records = await StudentRecord.find({}).sort({ createdAt: 1 });
    for (const record of records) {
        const canonicalData = `${record.apaar_hmac}|${record.student_id}|${record.institution_id}|${record.branch}|${record.admission_year}`;
        globalMerkleTree.appendRecord(canonicalData);
    }
    console.log(`Merkle Tree rehydrated with ${globalMerkleTree.leaves.length} records.`);
};

module.exports = {
    getPublicKey,
    signData,
    hashLeaf,
    globalMerkleTree,
    hashApaar,
    rehydrateMerkleTree
};
