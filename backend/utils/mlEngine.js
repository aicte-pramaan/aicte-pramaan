const StudentRecord = require('../models/StudentRecord');

// Built-in Jaro-Winkler Similarity Algorithm
const jaroWinkler = (s1, s2) => {
    s1 = s1.toLowerCase().trim();
    s2 = s2.toLowerCase().trim();
    if (s1 === s2) return 1.0;
    
    const len1 = s1.length;
    const len2 = s2.length;
    if (len1 === 0 || len2 === 0) return 0.0;

    const matchDistance = Math.floor(Math.max(len1, len2) / 2) - 1;
    const s1Matches = new Array(len1).fill(false);
    const s2Matches = new Array(len2).fill(false);
    let matches = 0;
    let trans = 0;

    for (let i = 0; i < len1; i++) {
        const start = Math.max(0, i - matchDistance);
        const end = Math.min(i + matchDistance + 1, len2);
        for (let j = start; j < end; j++) {
            if (s2Matches[j] || s1[i] !== s2[j]) continue;
            s1Matches[i] = true;
            s2Matches[j] = true;
            matches++;
            break;
        }
    }

    if (matches === 0) return 0.0;

    let k = 0;
    for (let i = 0; i < len1; i++) {
        if (!s1Matches[i]) continue;
        while (!s2Matches[k]) k++;
        if (s1[i] !== s2[k]) trans++;
        k++;
    }

    const jaro = (matches / len1 + matches / len2 + (matches - trans / 2) / matches) / 3;
    let prefix = 0;
    for (let i = 0; i < Math.min(4, Math.min(len1, len2)); i++) {
        if (s1[i] === s2[i]) prefix++;
        else break;
    }

    return jaro + prefix * 0.1 * (1 - jaro);
};

// 1. Cross-Institution Duplicate Admission Detection
const runFuzzyMatching = async (threshold = 0.85) => {
    const records = await StudentRecord.find({});
    const matches = [];

    for (let i = 0; i < records.length; i++) {
        for (let j = i + 1; j < records.length; j++) {
            const r1 = records[i];
            const r2 = records[j];

            if (r1.institution_id !== r2.institution_id) {
                const score = jaroWinkler(r1.name, r2.name);
                if (score >= threshold) {
                    matches.push({
                        similarity_score: (score * 100).toFixed(1) + '%',
                        record_1: { id: r1.student_id, name: r1.name, institution: r1.institution_id },
                        record_2: { id: r2.student_id, name: r2.name, institution: r2.institution_id }
                    });
                }
            }
        }
    }
    return matches;
};

// 2. Anomaly Scoring for Quota Stacking
const runIsolationForest = async () => {
    const records = await StudentRecord.find({});
    let flaggedCount = 0;

    for (const record of records) {
        const quotaConflictCount = (record.is_tfw ? 1 : 0) + (record.is_ews ? 1 : 0) + 
                                   (record.is_nri ? 1 : 0) + (record.is_fn ? 1 : 0);

        if (quotaConflictCount > 1) {
            record.ghost_flag = true;
            await record.save();
            flaggedCount++;
        }
    }

    return { status: "success", anomalies_flagged: flaggedCount };
};

module.exports = { runFuzzyMatching, runIsolationForest };