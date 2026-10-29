const nacl = require('tweetnacl');
const crypto = require('crypto');

const hashLeaf = (data) => {
    const prefix = Buffer.from([0x00]);
    return crypto.createHash('sha256')
        .update(Buffer.concat([prefix, Buffer.from(data)]))
        .digest();
};

const computePairHash = (leftBuffer, rightBuffer) => {
    const prefix = Buffer.from([0x01]);
    return crypto.createHash('sha256')
        .update(Buffer.concat([prefix, leftBuffer, rightBuffer]))
        .digest();
};

const verifyPayloadOffline = (qrPayload) => {
    console.log("\n==================================================");
    console.log("       OFFLINE CRYPTOGRAPHIC VERIFICATION         ");
    console.log("==================================================");
    
    const { version, public_key, apaar_hmac, data, signature, merkle_root, proof } = qrPayload;

    console.log(`Student ID   : ${data.student_id}`);
    console.log(`Student Name : ${data.name}`);
    console.log(`Institution  : ${data.institution_id}`);
    console.log(`Branch       : ${data.branch}`);

    // 1. Verify Ed25519 Digital Signature
    const dataBytes = new TextEncoder().encode(JSON.stringify(data));
    const sigBytes = Uint8Array.from(Buffer.from(signature, 'hex'));
    const pubKeyBytes = Uint8Array.from(Buffer.from(public_key, 'hex'));

    const isSignatureValid = nacl.sign.detached.verify(dataBytes, sigBytes, pubKeyBytes);
    console.log(`\n[1/2] Ed25519 Digital Signature : ${isSignatureValid ? 'VALID ✅' : 'INVALID ❌'}`);

    // 2. Reconstruct Merkle Root from Canonical Data and Path Proof
    const canonicalData = `${apaar_hmac}|${data.student_id}|${data.institution_id}|${data.branch}|${data.admission_year}`;
    let currentHash = hashLeaf(canonicalData);

    if (proof && proof.length > 0) {
        for (let i = 0; i < proof.length; i++) {
            const step = proof[i];
            const siblingHash = Buffer.from(step.sibling, 'hex');

            if (step.position === 'left') {
                currentHash = computePairHash(siblingHash, currentHash);
            } else {
                currentHash = computePairHash(currentHash, siblingHash);
            }
        }
    }

    const reconstructedRoot = currentHash.toString('hex');
    const isMerkleValid = (reconstructedRoot === merkle_root);
    console.log(`[2/2] Merkle Tree Path Proof    : ${isMerkleValid ? 'VALID ✅' : 'INVALID ❌'}`);

    console.log("--------------------------------------------------");
    if (isSignatureValid && isMerkleValid) {
        console.log("VERDICT: CREDENTIAL IS GENUINE & UNTAMPERED ✅");
    } else {
        console.log("VERDICT: CREDENTIAL FORGERY OR TAMPERING DETECTED ❌");
    }
    console.log("==================================================\n");
};

const runTest = async () => {
    try {
        const apaarId = process.argv[2] || "400050006000";
        const res = await fetch(`http://127.0.0.1:5000/api/records/generate-qr/${apaarId}`);
        const payload = await res.json();

        if (payload.error) {
            console.error("Cannot verify:", payload.error);
            return;
        }

        verifyPayloadOffline(payload);
    } catch (err) {
        console.error("Execution error:", err.message);
    }
};

runTest();
