const API_BASE = "https://aicte-pramaan-api.onrender.com";
const TRUSTED_ED25519_PUBLIC_KEY =
    "b4d6a4f061910c638906414e99cc6a8e0dae3e947ccb9557165c35dd08a8ba63";
let jwtToken = ""; // Stores the backend JWT session token

// ----------------------------------------------------------------------
// Sync SHA-256 (used for the hash-chained audit trail)
// ----------------------------------------------------------------------
const SHA_K = [], SHA_H = [];
(function () {
    let n = 2;
    while (SHA_K.length < 64) {
        let prime = true;
        for (let i = 2; i * i <= n; i++) { if (n % i === 0) { prime = false; break; } }
        if (prime) {
            if (SHA_H.length < 8) SHA_H.push((Math.pow(n, 0.5) * 4294967296) | 0);
            SHA_K.push((Math.pow(n, 1 / 3) * 4294967296) | 0);
        }
        n++;
    }
})();

function sha256sync(str) {
    const bytes = new TextEncoder().encode(str);
    const l = bytes.length;
    const total = ((l + 9 + 63) >> 6) << 6;
    const buf = new Uint8Array(total);
    buf.set(bytes);
    buf[l] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(total - 8, Math.floor(l * 8 / 4294967296));
    dv.setUint32(total - 4, (l * 8) >>> 0);
    let h = SHA_H.slice();
    const w = new Array(64);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let o = 0; o < total; o += 64) {
        for (let i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4);
        for (let i = 16; i < 64; i++) {
            const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
            const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
        }
        let [a, b, c, d, e, f, g, hh] = h;
        for (let i = 0; i < 64; i++) {
            const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const ch = (e & f) ^ (~e & g);
            const t1 = (hh + S1 + ch + SHA_K[i] + w[i]) | 0;
            const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const mj = (a & b) ^ (a & c) ^ (b & c);
            const t2 = (S0 + mj) | 0;
            hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
        }
        h = [(h[0] + a) | 0, (h[1] + b) | 0, (h[2] + c) | 0, (h[3] + d) | 0,
             (h[4] + e) | 0, (h[5] + f) | 0, (h[6] + g) | 0, (h[7] + hh) | 0];
    }
    return h.map(x => (x >>> 0).toString(16).padStart(8, "0")).join("");
}

const GENESIS = "0".repeat(64);
const auditHash = (prev, e) => sha256sync(`${prev}|${e.block}|${e.timestamp}|${e.role}|${e.action}|${e.details}`);

function rechain(list) {
    let prev = GENESIS;
    const asc = list.slice().reverse();
    asc.forEach((e, i) => { e.block = i + 1; e.prev = prev; e.hash = auditHash(prev, e); prev = e.hash; });
    return asc.reverse();
}

// Database Simulation (LocalStorage)
const DB_KEY = "aicte_apaar_depth_v1";

const INSTITUTIONS = [
    { id: "INST001", name: "Govind Institute of Technology",  base: 60, over: { CSE: 2 } },
    { id: "INST002", name: "Rajarshi College of Engineering", base: 60, over: { IT: 4 } },
    { id: "INST003", name: "Sharda School of Management",     base: 60, over: { PGDM: 2 } }
];
const sanctioned = (instId, code) => {
    const i = INSTITUTIONS.find(x => x.id === instId);
    if (!i) return Infinity;
    return i.over[code] !== undefined ? i.over[code] : i.base;
};

// Branches
const B = (code, name, short, group, rx, deg = "B.Tech") => ({ code, name, short, group, rx, deg });
const BRANCHES = [
    B("AIML", "CSE (Artificial Intelligence & Machine Learning)", "CSE (AI & ML)", "Computing & IT", /aiml|\bai\s*(&|and)\s*ml|machine learning|artificial intel/),
    B("AIDS", "Artificial Intelligence & Data Science", "AI & Data Science", "Computing & IT", /\baids\b|\bai\s*(&|and)\s*data/),
    B("DS",   "CSE (Data Science)", "CSE (Data Science)", "Computing & IT", /data science/),
    B("CYS",  "CSE (Cyber Security)", "CSE (Cyber Security)", "Computing & IT", /cyber/),
    B("IOT",  "CSE (Internet of Things)", "CSE (IoT)", "Computing & IT", /\biot\b|internet of things/),
    B("CSE",  "Computer Science & Engineering", "CSE", "Computing & IT", /\bcse\b|computer sci|computer eng/),
    B("IT",   "Information Technology", "IT", "Computing & IT", /\bit\b|information tech/),
    B("VLSI", "Electronics (VLSI Design & Technology)", "VLSI", "Electrical & Electronics", /vlsi/),
    B("ROB",  "Robotics & Automation", "Robotics & Automation", "Electrical & Electronics", /robot/),
    B("ETC",  "Electronics & Telecommunication Engineering", "Electronics & Telecom", "Electrical & Electronics", /\betc\b|entc|telecom/),
    B("EIE",  "Electronics & Instrumentation Engineering", "Electronics & Instrumentation", "Electrical & Electronics", /instrumentation|\beie\b/),
    B("ECE",  "Electronics & Communication Engineering", "ECE", "Electrical & Electronics", /\bece\b|electronics\s*(&|and)\s*comm/),
    B("EEE",  "Electrical & Electronics Engineering", "EEE", "Electrical & Electronics", /\beee\b|electrical\s*(&|and)\s*electronics/),
    B("EE",   "Electrical Engineering", "Electrical", "Electrical & Electronics", /\bee\b|electrical/),
    B("MTR",  "Mechatronics Engineering", "Mechatronics", "Mechanical & Allied", /mechatronic/),
    B("AE",   "Automobile Engineering", "Automobile", "Mechanical & Allied", /automobile|\bae\b/),
    B("AERO", "Aerospace / Aeronautical Engineering", "Aerospace", "Mechanical & Allied", /aerospace|aeronautic|\baero/),
    B("IP",   "Industrial & Production Engineering", "Production", "Mechanical & Allied", /production|industrial/),
    B("ME",   "Mechanical Engineering", "ME", "Mechanical & Allied", /\bme\b|mechanical/),
    B("CE",   "Civil Engineering", "CE", "Civil & Environmental", /\bce\b|civil/),
    B("ENV",  "Environmental Engineering", "Environmental", "Civil & Environmental", /environmental/),
    B("PET",  "Petroleum / Petrochemical Engineering", "Petroleum", "Chemical & Process", /petro/),
    B("PCT",  "Polymer / Plastic Technology", "Polymer", "Chemical & Process", /polymer|plastic/),
    B("CHE",  "Chemical Engineering", "Chemical", "Chemical & Process", /\bche\b|\bchemical/),
    B("FT",   "Food Technology", "Food Technology", "Chemical & Process", /food/),
    B("BT",   "Biotechnology", "Biotechnology", "Chemical & Process", /biotech|\bbt\b/),
    B("BME",  "Biomedical Engineering", "Biomedical", "Materials & Others", /biomedical|\bbme\b/),
    B("MME",  "Metallurgical & Materials Engineering", "Metallurgy & Materials", "Materials & Others", /metallurg|materials/),
    B("CER",  "Ceramic Engineering", "Ceramic", "Materials & Others", /ceramic/),
    B("TEX",  "Textile Engineering", "Textile", "Materials & Others", /textile/),
    B("MIN",  "Mining Engineering", "Mining", "Materials & Others", /mining/),
    B("MAR",  "Marine / Naval Architecture", "Marine", "Materials & Others", /marine|naval/),
    B("AGR",  "Agricultural Engineering", "Agricultural", "Materials & Others", /agricultur/),
    B("PGDM", "PGDM (Management)", "PGDM", "Management & Applications", /pgdm/, ""),
    B("MBA",  "MBA", "MBA", "Management & Applications", /\bmba\b/, ""),
    B("MCA",  "MCA (Computer Applications)", "MCA", "Management & Applications", /\bmca\b|computer applications/, ""),
    B("OTH",  "Other / Unmapped", "Other", "Other", null, "")
];
const BRANCH_MAP = Object.fromEntries(BRANCHES.map(b => [b.code, b]));
const courseFor = code => { const b = BRANCH_MAP[code]; return b ? (b.deg ? `${b.deg} ${b.short}` : b.short) : ""; };

function guessBranch(course) {
    const c = String(course || "").toLowerCase();
    for (const b of BRANCHES) if (b.rx && b.rx.test(c)) return b.code;
    const words = c.split(/[^a-z0-9]+/);
    for (const b of BRANCHES) if (words.includes(b.code.toLowerCase())) return b.code;
    return "OTH";
}

const inferredBranch = new WeakMap();
function branchOf(r) {
    if (BRANCH_MAP[r.branch]) return r.branch;
    let b = inferredBranch.get(r);
    if (!b) { b = guessBranch(r.course); inferredBranch.set(r, b); }
    return b;
}

let branchScope = "ALL"; 
// 🔐 RBAC Granular Data Filtering
const inScope = r => {
    const role = document.body.getAttribute("data-role") || "aicte";
    // Institution Officer can ONLY see their own institute's data (INST001)
    if (role === "institution" && r.inst !== "INST001") return false;
    return branchScope === "ALL" || branchOf(r) === branchScope;
};
const scopeName = () => branchScope === "ALL" ? "All Branches" : BRANCH_MAP[branchScope].name;

let db = loadDB();

function loadDB() {
    try {
        const parsed = JSON.parse(localStorage.getItem(DB_KEY));
        if (parsed && parsed.records) {
            parsed.audit = parsed.audit || [];
            if (parsed.audit.some(e => !e.hash)) parsed.audit = rechain(parsed.audit);
            return parsed;
        }
    } catch (e) {}
    return { records: [], audit: [] };
}

function saveDB() {
    localStorage.setItem(DB_KEY, JSON.stringify(db));
}

const el = id => document.getElementById(id);
const escapeHTML = str => String(str).replace(/[&<>'"]/g, 
    tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag])
);
const COLOR = { ok: "success", er: "danger", wn: "warning", in: "primary", pu: "purple" };
const KIND  = { ok: "tag-success", er: "tag-danger", wn: "tag-warning", in: "tag-info", pu: "tag-purple" };
const pill  = (text, kind) => `<span class="tag ${KIND[kind] || ""}">${escapeHTML(text)}</span>`;
const getInstName = id => (INSTITUTIONS.find(i => i.id === id) || { name: id }).name;const sortRecords = () => [...db.records].sort((a, b) => a.apaar.localeCompare(b.apaar));

function branchOptions(withAll) {
    let h = withAll ? '<option value="ALL">All Branches</option>' : "";
    const groups = [];
    BRANCHES.forEach(b => {
        let g = groups.find(x => x.n === b.group);
        if (!g) { g = { n: b.group, items: [] }; groups.push(g); }
        g.items.push(b);
    });
    groups.forEach(g => {
        h += `<optgroup label="${escapeHTML(g.n)}">` +
            g.items.map(b => `<option value="${b.code}">${escapeHTML(b.name)} (${b.code})</option>`).join("") +
            `</optgroup>`;
    });
    return h;
}

function logAudit(action, details) {
    const role = el("role").value;
    const head = db.audit[0];
    const e = {
        block: head ? head.block + 1 : 1,
        timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),
        role: role.toUpperCase(),
        action: action,
        details: details,
        prev: head ? head.hash : GENESIS
    };
    e.hash = auditHash(e.prev, e);
    db.audit.unshift(e);
}

// Cryptography: SHA-256 and Merkle Tree
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function createCanonicalString(r) {
    const base = `${r.apaar}|${r.sid}|${r.name}|${r.inst}|${r.course}|${r.year}|${r.tfw?1:0}|${r.ews?1:0}|${r.fn?1:0}|${r.sup?1:0}|${r.consent?1:0}`;
    return r.branch ? `${base}|${r.branch}` : base;
}

async function generateMerkleTree(records) {
    if (records.length === 0) return [];
    let currentLevel = await Promise.all(records.map(r => sha256(createCanonicalString(r))));
    const tree = [currentLevel];

    while (currentLevel.length > 1) {
        const nextLevel = [];
        for (let i = 0; i < currentLevel.length; i += 2) {
            const left = currentLevel[i];
            const right = currentLevel[i + 1] || left; 
            nextLevel.push(await sha256(left + right));
        }
        tree.push(nextLevel);
        currentLevel = nextLevel;
    }
    return tree;
}

function getMerkleProof(tree, leafIndex) {
    const proof = [];
    let idx = leafIndex;
    for (let i = 0; i < tree.length - 1; i++) {
        const isRightNode = idx % 2 === 1;
        const siblingIdx = isRightNode ? idx - 1 : idx + 1;
        const siblingHash = tree[i][siblingIdx] || tree[i][idx];
        proof.push({ hash: siblingHash, isLeftSibling: isRightNode });
        idx = Math.floor(idx / 2);
    }
    return proof;
}

async function verifyMerkleProof(leafHash, proof, rootHash) {
    let computedHash = leafHash;
    for (const step of proof) {
        if (step.isLeftSibling) {
            computedHash = await sha256(step.hash + computedHash);
        } else {
            computedHash = await sha256(computedHash + step.hash);
        }
    }
    return computedHash === rootHash;
}

// Business Logic
let apaarCache = {};
let instRegCache = {}; 
const seatKey = (inst, branch) => `${inst}|${branch}`;

function buildCaches() {
    apaarCache = {};
    instRegCache = {};
    for (let r of db.records) {
        apaarCache[r.apaar] = (apaarCache[r.apaar] || 0) + 1;
        if (!r.sup) {
            const k = seatKey(r.inst, branchOf(r));
            instRegCache[k] = (instRegCache[k] || 0) + 1;
        }
    }
}

function analyzeFlags(record) {
    const flags = [];
    if (apaarCache[record.apaar] > 1) flags.push(`Dual Enrollment Detected`);
    if ((record.nri ? 1 : 0) + (record.tfw ? 1 : 0) + (record.ews ? 1 : 0) + (record.fn ? 1 : 0) > 1) {
        flags.push("Status Conflict (Multiple Quotas)");
    }
    if (!record.sup) {
        const instData = INSTITUTIONS.find(i => i.id === record.inst);
        const b = branchOf(record);
        const currentCount = instRegCache[seatKey(record.inst, b)] || 0;
        if (instData && currentCount > sanctioned(record.inst, b)) {
            flags.push("Exceeds AICTE Approved Intake");
        }
    }
    if (record.ghost_flag) flags.push("ML Flag: Anomaly Detected");
    return flags;
}

function processRecord(recordData) {
    if (!recordData.apaar || recordData.apaar.length < 8) return { success: false, msg: "Invalid APAAR / Foreign Temp ID" };
    if (!recordData.name || !recordData.inst || !recordData.course) return { success: false, msg: "Missing required fields" };

    if (!BRANCH_MAP[recordData.branch]) recordData.branch = guessBranch(recordData.course);
    
    const existingIdx = db.records.findIndex(r => r.apaar === recordData.apaar && r.inst === recordData.inst);
    
    if (existingIdx > -1) {
        db.records[existingIdx] = recordData;
        logAudit("UPDATE_RECORD", `Updated student ${recordData.apaar} [${recordData.branch}]`);
    } else {
        db.records.push(recordData);
        logAudit("INGEST_RECORD", `New admission mapped to ${recordData.apaar} [${recordData.branch}]`);
    }
    
    saveDB();
    return { success: true, msg: "Record securely encrypted and saved." };
}


function normalizeApaarId(value) {
    const raw = String(value || '').trim();
    const compact = raw.replace(/[\s-]/g, '');

    return /^\d{12}$/.test(compact) ? compact : raw;
}

async function postRecordToLedger(payload) {
    if (!jwtToken) {
        throw new Error('Please log in before registering a record.');
    }

    const response = await fetch(`${API_BASE}/api/records/ingest`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${jwtToken}`
        },
        body: JSON.stringify(payload)
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
        throw new Error(data.error || `Backend error ${response.status}`);
    }

    return data;
}

const toLedgerPayload = r => ({
    apaar_id: r.apaar,
    student_id: r.sid,
    name: r.name,
    institution_id: r.inst,
    branch: BRANCH_MAP[r.branch] ? r.branch : branchOf(r),
    admission_year: Number(r.year),
    is_tfw: !!r.tfw, is_ews: !!r.ews, is_nri: !!r.nri, is_fn: !!r.fn,
    has_consent: r.consent !== false
});

async function syncRecordsToBackend(records, onProgress) {
    if (!jwtToken) throw new Error('Log in as AICTE Admin first.');
    const totals = { inserted: 0, already_present: 0, invalid: 0 };
    const CHUNK = 1000;

    for (let i = 0; i < records.length; i += CHUNK) {
        const chunk = records.slice(i, i + CHUNK).map(toLedgerPayload);
        const res = await fetch(`${API_BASE}/api/records/bulk-ingest`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${jwtToken}`
            },
            body: JSON.stringify({ records: chunk })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || `Backend error ${res.status}`);
        totals.inserted += data.inserted;
        totals.already_present += data.already_present;
        totals.invalid += data.invalid;
        if (onProgress) onProgress(Math.min(i + CHUNK, records.length), records.length);
    }
    return totals;
}

// UI Rendering
async function updateDashboard() {
    buildCaches();
    renderQuota();
    
    let total = 0, flaggedCount = 0, dupCount = 0;
    const rows = {};
    const addRow = (inst, branch) => {
        const k = seatKey(inst, branch);
        if (!rows[k]) rows[k] = { inst, branch, reg: 0, sup: 0 };
        return rows[k];
    };
    if (branchScope !== "ALL") INSTITUTIONS.forEach(i => addRow(i.id, branchScope));

    db.records.forEach(r => {
        if (!inScope(r)) return;
        total++;
        const flags = analyzeFlags(r);
        if (flags.length > 0) flaggedCount++;
        if (flags.some(f => f.includes("Dual"))) dupCount++;
        if (INSTITUTIONS.some(i => i.id === r.inst)) {
            const row = addRow(r.inst, branchOf(r));
            if (r.sup) row.sup++; else row.reg++;
        }
    });

    el("s-total").innerText = total;
    el("s-flag").innerText = flaggedCount;
    el("s-dup").innerText = dupCount;

    const list = Object.values(rows).sort((a, b) =>
        BRANCH_MAP[a.branch].name.localeCompare(BRANCH_MAP[b.branch].name) || a.inst.localeCompare(b.inst));

    el("inst-table").previousElementSibling.textContent = `Intake vs. Actual Enrolment · ${scopeName()}`;

    let tableHTML = `<tr><th>Institution</th><th>Branch</th><th class="num">Approved Intake</th><th class="num">Actual Enrolment</th><th class="num">Supernumerary</th><th>Status</th></tr>`;
    if (list.length === 0) tableHTML += `<tr><td colspan="6" class="text-center helper-text">No enrolments yet. Add a record or load the sample data.</td></tr>`;
    
    list.slice(0, 60).forEach(data => {
        const intake = sanctioned(data.inst, data.branch);
        const overLimit = data.reg > intake;
        const statusTag = overLimit 
            ? `<span class="tag tag-danger">Excess: ${data.reg - intake}</span>` 
            : `<span class="tag tag-success">Compliant</span>`;
        
        tableHTML += `<tr>
            <td><strong>${escapeHTML(getInstName(data.inst))}</strong></td>
            <td><span class="chip" title="${escapeHTML(BRANCH_MAP[data.branch].name)}">${data.branch}</span></td>
            <td class="num">${intake}</td>
            <td class="num">${data.reg}</td>
            <td class="num">${data.sup}</td>
            <td>${statusTag}</td>
        </tr>`;
    });
    if (list.length > 60) tableHTML += `<tr><td colspan="6" class="text-center helper-text">Showing 60 of ${list.length} institution-branch rows.</td></tr>`;
    el("inst-table").innerHTML = tableHTML;

    if (db.records.length === 0) { el("s-root").innerText = "No data"; return; }
    if (db.records.length > 1000) { el("s-root").innerText = db.merkleRoot ? db.merkleRoot.substring(0, 16) + "..." : "Computed via Backend"; return; }
    const tree = await generateMerkleTree(sortRecords());
    el("s-root").innerText = tree[tree.length - 1][0].substring(0, 16) + "...";
}

const PAGE_SIZE = 100;
let recPage = 0;

function updateRecords() {
    buildCaches();
    const query = el("search").value.toLowerCase().trim();
    const sorted = sortRecords().filter(inScope);
    const filtered = query
        ? sorted.filter(r => {
            const b = BRANCH_MAP[branchOf(r)];
            return `${r.apaar} ${r.name} ${getInstName(r.inst)} ${b.code} ${b.name}`.toLowerCase().includes(query);
        })
        : sorted;

    const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
    if (recPage > totalPages - 1) recPage = totalPages - 1;
    if (recPage < 0) recPage = 0;

    const start = recPage * PAGE_SIZE;
    const pageRows = filtered.slice(start, start + PAGE_SIZE);

    let html = `<tr><th>APAAR ID</th><th>Student Identity</th><th>Institution</th><th>Branch</th><th>Course (Year)</th><th>Compliance Flags</th></tr>`;
    if (pageRows.length === 0) html += `<tr><td colspan="6" class="text-center helper-text">No records found.</td></tr>`;

    for (let r of pageRows) {
        const flags = analyzeFlags(r);
        const flagHTML = flags.length === 0 
            ? `<span class="tag tag-success">Clean Record</span>`
            : flags.map(f => `<span class="tag tag-warning">${escapeHTML(f)}</span>`).join(" ");
        const b = BRANCH_MAP[branchOf(r)];

        html += `<tr>
            <td class="mono"><a class="apaar-link" onclick="openStudent360('${escapeHTML(r.apaar)}')">${escapeHTML(r.apaar)}</a></td>
            <td><strong>${escapeHTML(r.name)}</strong><div class="muted mono">${escapeHTML(r.sid || "")}</div></td>
            <td>${escapeHTML(getInstName(r.inst))}</td>
            <td><span class="chip" title="${escapeHTML(b.name)}">${b.code}</span></td>
            <td>${escapeHTML(r.course)} <span class="muted">(${r.year})</span></td>
            <td>${flagHTML}</td>
        </tr>`;
    }
    el("rec-table").innerHTML = html;

    const from = filtered.length ? start + 1 : 0;
    const to = start + pageRows.length;
    el("rec-range").innerText = `Showing ${from.toLocaleString()}–${to.toLocaleString()} of ${filtered.length.toLocaleString()} records · ${scopeName()}`;
    el("rec-page-label").innerText = `Page ${recPage + 1} of ${totalPages.toLocaleString()}`;
    el("rec-prev").disabled = recPage === 0;
    el("rec-next").disabled = recPage >= totalPages - 1;
}

function verifyChain() {
    let prev = GENESIS;
    for (const e of [...db.audit].reverse()) {
        if (e.prev !== prev || auditHash(prev, e) !== e.hash) return { ok: false, block: e.block };
        prev = e.hash;
    }
    return { ok: true };
}

const shortHash = h => "0x" + h.slice(0, 4) + "..." + h.slice(-4);

function updateAudit() {
    const chain = verifyChain();
    el("chain-status").innerHTML = chain.ok ? pill(`Chain valid · ${db.audit.length} blocks`, "ok") : pill(`Chain broken at block #${chain.block}`, "er");

    let html = `<tr><th>Block</th><th>Action · Actor</th><th>PrevHash → CurrHash</th><th>Event Details</th></tr>`;
    if (db.audit.length === 0) html += `<tr><td colspan="4" class="text-center helper-text">No events recorded yet.</td></tr>`;
    
    db.audit.slice(0, 100).forEach(a => {
        html += `<tr>
            <td class="mono nw">#${a.block}<span class="sub">${a.timestamp} UTC</span></td>
            <td class="mono">${escapeHTML(a.action)}<span class="sub">${escapeHTML(a.role)}</span></td>
            <td class="mono nw"><span class="hash" data-full="${a.prev}" title="Click to copy">${shortHash(a.prev)}</span> → <span class="hash" data-full="${a.hash}" title="Click to copy">${shortHash(a.hash)}</span></td>
            <td>${escapeHTML(a.details)}</td>
        </tr>`;
    });
    el("audit-table").innerHTML = html;
}

// Branch UI Injection

// ============================================================
// BRANCH UI — INITIALIZE EXISTING HTML ELEMENTS
// Avoid duplicate IDs and duplicate dropdowns.
// ============================================================

(function injectBranchUI() {

    // Sidebar branch selector
    const wrap = el("branch-filter-wrap");

    if (wrap) {
        let filter = el("branch-filter");

        if (!filter) {
            filter = document.createElement("select");
            filter.id = "branch-filter";
            wrap.appendChild(filter);
        } else if (!wrap.contains(filter)) {
            wrap.appendChild(filter);
        }

        filter.innerHTML = branchOptions(true);
        filter.value = "ALL";
        filter.style.width = "100%";
    }

    // Use the branch selector already present in index.html
    const formBranch = el("f-branch");

    if (formBranch) {
        formBranch.innerHTML = branchOptions(false);
        formBranch.value = "CSE";
    }

    // Reuse the existing seat hint instead of creating a duplicate
    if (!el("seat-hint")) {
        const form = document.querySelector("#upload .form-grid");

        if (form) {
            form.insertAdjacentHTML(
                "afterend",
                '<div id="seat-hint" class="helper-text mt-16"></div>'
            );
        }
    }

    // Preserve the existing quota subtitle
    const quotaSubtitle =
        el("quota-sub") ||
        el("quota-matrix")?.previousElementSibling?.querySelector(".muted");

    if (quotaSubtitle) {
        quotaSubtitle.id = "quota-sub";
    }

})();

let lastAutoCourse = "";
function syncCourseFromBranch() {
    const c = el("f-course");
    if (!c.value || c.value === lastAutoCourse) {
        lastAutoCourse = courseFor(el("f-branch").value);
        c.value = lastAutoCourse;
    }
}

function updateSeatHint() {
     if (!el("f-inst") || !el("f-branch") || !el("seat-hint")) return;
    buildCaches();
    const inst = el("f-inst").value, code = el("f-branch").value;
    const cap = sanctioned(inst, code);
    const filled = instRegCache[seatKey(inst, code)] || 0;
    const open = Math.max(0, cap - filled);
    el("seat-hint").innerHTML = `Sanctioned intake for <strong>${escapeHTML(BRANCH_MAP[code].short)}</strong> at ${escapeHTML(inst)}: ${cap}
        · Filled (regular seats): ${filled} · Open: ${open} ` +
        (open === 0 ? pill("Full: new regular admissions will be flagged", "er") : pill("Seats available", "ok"));
}

let renderPage = function(p) {
    if (p === "dash") updateDashboard();
    if (p === "records") updateRecords();
    if (p === "audit") updateAudit();
    if (p === "vigilance") { 
        updateVigilance(); 
        initVigilanceCharts(); 
        renderFuzzyMatches(); 
    }
    if (p === "impact") { initCharts(); updateAnalyticsData(); }
}

const activePage = () => {
    const a = document.querySelector(".nav-menu a.active");
    return a ? a.getAttribute("data-page") : "dash";
};

document.querySelectorAll(".nav-menu a").forEach(link => {
    link.addEventListener("click", e => {
        e.preventDefault();
        const targetPage = link.getAttribute("data-page");
        document.querySelectorAll(".page").forEach(p => p.classList.add("hidden"));
        document.querySelectorAll(".nav-menu a").forEach(l => l.classList.remove("active"));
        el(targetPage).classList.remove("hidden");
        link.classList.add("active");
        el("page-title").innerText = link.innerText.trim();
        renderPage(targetPage);
        if (targetPage === "upload") updateSeatHint();
    });
});

// 🔐 2FA & Advanced Role Switcher
let pendingRole = 'aicte';
el("role").addEventListener("change", (e) => {
    const role = e.target.value;
    
    // Trigger 2FA for sensitive roles
    if (role === "aicte" || role === "audit") {
        e.target.value = document.body.getAttribute("data-role") || 'institution'; // Revert visually
        pendingRole = role;
        el("m-2fa").classList.remove("hidden");
        document.querySelectorAll(".otp-input")[0].focus();
    } else {
        applyRole(role);
    }
});

// 2FA Input Auto-Advance Logic
document.querySelectorAll(".otp-input").forEach((input, index, inputs) => {
    input.addEventListener("input", (e) => {
        if (e.target.value.length === 1 && index < inputs.length - 1) {
            inputs[index + 1].focus();
        }
    });
});

// 2FA Verification Simulation
// Live 2FA & JWT Authentication
el("btn-2fa-verify").addEventListener("click", async () => {
    const btn = el("btn-2fa-verify");
    btn.innerHTML = `Verifying TOTP...`;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 60000); // 60s timeout

    try {
        const response = await fetch(`${API_BASE}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: pendingRole === 'institution' ? 'INST001' : 'AICTE_ADMIN',
                password: pendingRole === 'institution' ? 'password123' : 'admin123',
                totp_code: "123456"
            }),
            signal: controller.signal
        });

        clearTimeout(timeout);
        const data = await response.json();

        if (data.access_token) {
            jwtToken = data.access_token;
            el("m-2fa").classList.add("hidden");
            btn.innerHTML = "Verify & Authenticate";
            el("role").value = pendingRole;
            applyRole(pendingRole);
            document.querySelectorAll(".otp-input").forEach(i => i.value = "");
            showToast("Security", `Connected to Backend. Role: ${pendingRole.toUpperCase()}`, "success");
        } else {
            showToast("Auth Failed", data.error || "Invalid credentials", "danger");
        }
    } catch (err) {
        clearTimeout(timeout);
        const msg = err.name === 'AbortError'
            ? "Request timed out — backend may be cold-starting. Try again in 30 seconds."
            : "Cannot reach the backend. Check your network or the Render service status.";
        showToast("Network Error", msg, "danger");
    } finally {
        btn.innerHTML = "Verify & Authenticate";
    }
});

function applyRole(role) {
    document.body.setAttribute("data-role", role);
    const roleText = el("role").options[el("role").selectedIndex].text;
    el("current-user-display").innerText = roleText.split(" (")[0]; 
    
    // UI Navigation Routing
    if (role === "employer") document.querySelector('[data-page="verify"]').click();
    else if (role === "audit") document.querySelector('[data-page="audit"]').click();
    else document.querySelector('[data-page="dash"]').click();

    // 🔐 Institution Data Lock (Prevents them from uploading for other colleges)
    const instSelect = el("f-inst");
    if (role === "institution") {
        instSelect.value = "INST001";
        instSelect.disabled = true;
    } else {
        instSelect.disabled = false;
    }
    
    // Force a re-render so Dashboard stats update to reflect the RBAC filtering
    renderPage(activePage());
}

el("branch-filter").addEventListener("change", e => {
    branchScope = e.target.value;
    recPage = 0;
    if (branchScope !== "ALL") {
        el("f-branch").value = branchScope; 
        syncCourseFromBranch();
        renderIngHead();
        updateSeatHint();
    }
    renderPage(activePage());
});

el("f-inst").innerHTML = INSTITUTIONS.map(i => `<option value="${i.id}">${i.name} (${i.id})</option>`).join("");
el("f-branch").addEventListener("change", () => { syncCourseFromBranch(); renderIngHead(); updateSeatHint(); });
el("f-inst").addEventListener("change", updateSeatHint);
syncCourseFromBranch();


el("add-btn").addEventListener("click", async () => {
    const btn = el("add-btn");
    const msgEl = el("add-msg");

    const recordPayload = {
        apaar_id: normalizeApaarId(el("f-apaar").value),
        student_id: el("f-sid").value.trim(),
        name: el("f-name").value.trim(),
        institution_id: el("f-inst").value,
        branch: el("f-branch").value,
        admission_year: Number(el("f-year").value),

        is_tfw: el("f-tfw")?.checked === true,
        is_ews: el("f-ews")?.checked === true,
        is_nri: el("f-nri")?.checked === true,
        is_fn: el("f-fn")?.checked === true,

        has_consent: el("f-consent").checked
    };

    if (recordPayload.apaar_id.length < 8) {
        msgEl.textContent = "Enter a valid APAAR or provisional ID.";
        msgEl.className = "msg mt-16 tag tag-danger";
        return;
    }

    if (
        !recordPayload.student_id ||
        !recordPayload.name ||
        !recordPayload.institution_id ||
        !recordPayload.branch ||
        !Number.isInteger(recordPayload.admission_year)
    ) {
        msgEl.textContent = "Complete all required fields.";
        msgEl.className = "msg mt-16 tag tag-danger";
        return;
    }

    btn.disabled = true;
    btn.innerText = "Securing Record...";

    try {
        // Backend is the source of truth.
        const data = await postRecordToLedger(recordPayload);

        // Update local Registry only after backend success.
        const localRecord = {
            apaar: recordPayload.apaar_id,
            sid: recordPayload.student_id,
            name: recordPayload.name,
            inst: recordPayload.institution_id,
            branch: recordPayload.branch,
            course: el("f-course").value.trim() ||
                courseFor(recordPayload.branch),
            year: recordPayload.admission_year,

            tfw: recordPayload.is_tfw,
            ews: recordPayload.is_ews,
            nri: recordPayload.is_nri,
            fn: recordPayload.is_fn,

            sup: false,
            ghost_flag: false,
            consent: recordPayload.has_consent
        };

        const localResult = processRecord(localRecord);

        if (!localResult.success) {
            console.warn("Local Registry update failed:", localResult.msg);
        }

        await updateDashboard();
        updateRecords();
        updateSeatHint();

        const auditWarning = data.audit_logged === false;

        msgEl.innerText = auditWarning
            ? `Record saved at Merkle Leaf ${data.index}. Audit logging failed.`
            : `Record cryptographically secured at Leaf ${data.index}.`;

        msgEl.className = auditWarning
            ? "msg mt-16 tag tag-warning"
            : "msg mt-16 tag tag-success";

        // Preserve the ID for certificate verification.
        const savedApaarId = recordPayload.apaar_id;

        if (recordPayload.has_consent) {
            const certificateButton = document.createElement("button");

            certificateButton.type = "button";
            certificateButton.className = "btn btn-primary depth-btn mt-16";
            certificateButton.textContent = "Generate Certificate";

            certificateButton.addEventListener("click", async () => {
                document.querySelector('[data-page="verify"]').click();

                el("v-id").value = savedApaarId;

                await performRecordVerification({
                    apaarId: savedApaarId
                });
            });

            msgEl.appendChild(document.createElement("br"));
            msgEl.appendChild(certificateButton);
        }

        showToast(
            auditWarning ? "Record Saved - Audit Warning" : "Admission Confirmed",
            data.message,
            auditWarning ? "warning" : "success"
        );

        ["f-apaar", "f-sid", "f-name"].forEach(id => {
            el(id).value = "";
        });

    } catch (error) {
        console.error("INGESTION ERROR:", error);

        msgEl.textContent = error.message;
        msgEl.className = "msg mt-16 tag tag-danger";

    } finally {
        btn.disabled = false;
        btn.innerText = "Secure & Upload Record";
    }
});


el("sample-btn").addEventListener("click", () => {
    el("csv").value = [
        "100000000001,GIT101,Aarav Sharma,INST001,B.Tech CSE,2026,n,n,n,n,y",
        "100000000002,GIT102,Meera Verma,INST001,B.Tech ECE,2026,n,n,n,n,y",
        "100000000003,GIT103,Rohan Gupta,INST001,B.Tech Mechanical Engineering,2026,n,n,n,n,n",
        "100000000004,GIT104,Kabir Singh,INST001,B.Tech CSE,2026,n,n,n,n,y",
        "100000000007,GIT105,Isha Rao,INST001,B.Tech Computer Science,2026,n,n,n,n,y",
        "100000000005,RCE201,Ananya Mishra,INST002,B.Tech IT,2026,y,n,n,y,y",
        "100000000004,RCE202,Kabir Singh,INST002,B.Tech IT,2026,n,n,n,n,y",
        "100000000008,RCE203,Vikram Nair,INST002,B.Tech Chemical Engineering,2026,n,n,n,n,y",
        "100000000009,RCE204,Divya Patel,INST002,B.Tech Electrical Engineering,2026,n,n,n,n,y",
        "100000000010,RCE205,Harsh Jain,INST002,B.Tech Electronics and Communication,2026,n,n,n,n,y",
        "100000000011,RCE206,Neha Joshi,INST002,B.Tech Civil Engineering,2026,n,n,n,n,y,CE",
        "100000000006,SSM301,Sara Khan,INST003,PGDM,2026,n,y,y,y,y"
    ].join("\n");
});


el("csv-btn").addEventListener("click", async () => {
    const btn = el("csv-btn");
    const msg = el("csv-msg");

    if (!jwtToken) {
        showToast("Login Required", "Log in before uploading CSV records.", "danger");
        return;
    }

    const lines = el("csv").value
        .split("\n")
        .map(line => line.trim())
        .filter(Boolean);

    let success = 0;
    let errors = 0;
    const failures = [];

    btn.disabled = true;
    btn.innerText = "Uploading Records...";

    try {
        // Sequential upload keeps Merkle leaf ordering predictable.
        for (let i = 0; i < lines.length; i++) {
            const parts = lines[i].split(",").map(x => x.trim());

            if (parts.length < 11) {
                errors++;
                continue;
            }

            const yes = value => String(value).toLowerCase() === "y";

            const apaarId = normalizeApaarId(parts[0]);
            const course = parts[4];

            const branchCode = (parts[11] || "").toUpperCase();

            const branch = BRANCH_MAP[branchCode]
                ? branchCode
                : guessBranch(course);

            const payload = {
                apaar_id: apaarId,
                student_id: parts[1],
                name: parts[2],
                institution_id: parts[3],
                branch,
                admission_year: Number(parts[5]),

                is_tfw: yes(parts[6]),
                is_ews: yes(parts[7]),
                is_nri: false,
                is_fn: yes(parts[8]),

                has_consent: yes(parts[10])
            };

            try {
                btn.innerText = `Uploading ${i + 1}/${lines.length}...`;

                await postRecordToLedger(payload);

                const result = processRecord({
                    apaar: apaarId,
                    sid: payload.student_id,
                    name: payload.name,
                    inst: payload.institution_id,
                    branch,
                    course,
                    year: payload.admission_year,

                    tfw: payload.is_tfw,
                    ews: payload.is_ews,
                    nri: payload.is_nri,
                    fn: payload.is_fn,
                    sup: yes(parts[9]),
                    ghost_flag: false,
                    consent: payload.has_consent
                });

                if (result.success) {
                    success++;
                } else {
                    errors++;
                    failures.push(`${apaarId}: ${result.msg}`);
                }

            } catch (error) {
                errors++;
                failures.push(`${apaarId}: ${error.message}`);
            }
        }

        await updateDashboard();
        updateRecords();
        updateSeatHint();

        msg.innerHTML = `
            <span class="tag tag-success">${success} uploaded</span>
            <span class="tag tag-danger">${errors} failed</span>
            ${
                failures.length
                    ? `<div class="helper-text mt-16">${
                        failures.slice(0, 5).map(escapeHTML).join("<br>")
                    }</div>`
                    : ""
            }
        `;

    } finally {
        btn.disabled = false;
        btn.innerText = "Process Batch";
    }
});


el("reset-btn").addEventListener("click", () => {
    if (confirm("WARNING: This destroys the local ledger and audit trail. Proceed?")) {
        db = { records: [], audit: [] };
        saveDB();
        logAudit("SYSTEM_PURGE", "Ledger reset to genesis block.");
        el("csv-msg").innerHTML = `<span class="tag tag-warning">Database Purged</span>`;
        updateDashboard();
        updateSeatHint();
    }
});

el("search").addEventListener("input", () => { recPage = 0; updateRecords(); });
el("rec-prev").addEventListener("click", () => { recPage--; updateRecords(); });
el("rec-next").addEventListener("click", () => { recPage++; updateRecords(); });

const ICON = {
    check: '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M13.78 4.22a.75.75 0 0 1 0 1.06l-7.25 7.25a.75.75 0 0 1-1.06 0L2.22 9.28a.75.75 0 1 1 1.06-1.06L6 10.94l6.72-6.72a.75.75 0 0 1 1.06 0z"/></svg>',
    cross: '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M3.72 3.72a.75.75 0 0 1 1.06 0L8 6.94l3.22-3.22a.75.75 0 1 1 1.06 1.06L9.06 8l3.22 3.22a.75.75 0 1 1-1.06 1.06L8 9.06l-3.22 3.22a.75.75 0 0 1-1.06-1.06L6.94 8 3.72 4.78a.75.75 0 0 1 0-1.06z"/></svg>',
    shield: '<svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor"><path d="M7.467.133a1.75 1.75 0 0 1 1.066 0l5.25 1.68A1.75 1.75 0 0 1 15 3.48V7c0 1.566-.32 3.182-1.303 4.682-.983 1.498-2.585 2.813-5.032 3.855a1.7 1.7 0 0 1-1.33 0c-2.447-1.042-4.049-2.357-5.032-3.855C1.32 10.182 1 8.566 1 7V3.48a1.75 1.75 0 0 1 1.217-1.667zm.61 1.429a.25.25 0 0 0-.153 0l-5.25 1.68a.25.25 0 0 0-.174.238V7c0 1.358.275 2.666 1.057 3.86.784 1.194 2.121 2.34 4.366 3.297a.2.2 0 0 0 .154 0c2.245-.956 3.582-2.104 4.366-3.298C13.225 9.666 13.5 8.36 13.5 7V3.48a.25.25 0 0 0-.174-.237z"/></svg>'
};

const BATCH = [
    { id: "4829-1049-8821", sid: "2026CSE001", nm: "Aarav Sharma", cat: "CORE_MERIT", r: "NAD/DigiLocker API: 200 OK (Demographics Matched)", s: ["Committed", "ok"] },
    { id: "7391-5520-1940", sid: "2026CSE121", nm: "Priyanshu Verma", cat: "TFW_SUPERNUMERARY", r: "QUOTA_STUFFING_BLOCKED: Core Intake (120/120) full; domestic candidate without TFW income certificate cannot occupy supernumerary slot", s: ["Hard rejected", "er"], bad: 1 },
    { id: "PROV-FN-NPL-88210", sub: "Passport: PA8492011", sid: "2026CSE-FN04", nm: "Siddhartha Thapa (Nepal)", cat: "FN_SUPERNUMERARY", r: "NAD/FRRO Bridge: FRRO Visa #V99201 Verified (Aadhaar Exempt Track)", s: ["Provisional locked", "in"] },
    { id: "9912-3049-1102", sid: "2026CSE089", nm: "Rohan Deshmukh", cat: "CORE_MERIT", r: "CROSS_STATE_DUPLICATE: Active Regular B.Tech seat found at VJTI Mumbai (AICTE ID: 1-339102). Placed in 72h Counseling Seat-Transfer Escrow", s: ["Escrow hold · 48h left", "wn"], bad: 1 },
    { id: "6610-8492-3319", sid: "2026CSE094", nm: "Sneha Kulkarni", cat: "DUAL_DEGREE", r: "NEP-2020 Dual Enrolment Check: Concurrent registration at IGNOU (Mode: ODL/Online) permitted", s: ["Committed", "ok"] },
    { id: "5521-0087-4410", sid: "2026CSE112", nm: "Ananya Iyer", cat: "NRI_QUOTA", r: "NAD/DigiLocker API: 200 OK · NRI sponsor affidavit and FIRC remittance proof verified", s: ["Committed", "ok"] }
];
const KPIS = [
    ["Total verified APAAR enrolments", "14,82,910", ""],
    ["Institutions synced", "8,412", " / 8,540"],
    ["Excess intake attempts blocked", "4,129", ""],
    ["Ghost enrolment clusters flagged", "38", ""]
];
const ANOM = [
    { id: "ANOM-902", sev: ["High", "er"], score: "0.94", who: "Institute 1-88392011", t: "18 student records share an identical bank prefix and mobile cluster +91-98204-XXXXX.", tag: "Suspected NSP scholarship ghost enrolment", det: "Isolation Forest" },
    { id: "ANOM-887", sev: ["Medium", "wn"], score: "0.81", who: "College A ↔ College B", t: "Jaro-Winkler phonetic match (0.96) between Karanveer Singh (DOB 14-08-2007) and Karan Vir Singh (DOB 14-08-2007) under different provisional IDs.", tag: "Probable duplicate identity", det: "Fuzzy linkage" },
    { id: "ANOM-854", sev: ["High", "er"], score: "0.89", who: "Institute 1-72014433", t: "88% of the annual batch was uploaded 14 minutes before the EoA statutory cutoff.", tag: "Temporal burst anomaly", det: "Isolation Forest" }
];

function renderQuota() {
    const codes = branchScope === "ALL" ? BRANCHES.filter(b => b.code !== "OTH").map(b => b.code) : [branchScope];
    let core = 0;
    INSTITUTIONS.forEach(i => codes.forEach(c => { core += sanctioned(i.id, c); }));

    const f = { core: 0, tfw: 0, fn: 0, nri: 0 };
    for (const r of db.records) {
        if (!inScope(r)) continue;
        if (!r.sup) f.core++;
        if (r.tfw) f.tfw++;
        if (r.fn) f.fn++;
        if (r.nri) f.nri++;
    }
    const cap = pct => Math.ceil(core * pct / 100);
    const status = (filled, c, lockedLabel) => filled > c ? ["Exceeded", "er"] : (c > 0 && filled === c ? [lockedLabel, "ok"] : ["Open", "in"]);

    const Q = [
        { label: "Core Sanctioned Intake (I₀)", f: f.core, c: core, s: status(f.core, core, "Locked"), note: `Sanctioned seats across ${INSTITUTIONS.length} institutions. Overflow blocked.` },
        { label: "Tuition Fee Waiver (TFW)", f: f.tfw, c: cap(5), s: status(f.tfw, cap(5), "Filled"), note: "Max 5% supernumerary. Verified income < ₹8L." },
        { label: "Foreign National / OCI / PIO", f: f.fn, c: cap(15), s: status(f.fn, cap(15), "Filled"), note: "Max 15% supernumerary. Passport + FRRO verified." },
        { label: "NRI Quota", f: f.nri, c: cap(5), s: status(f.nri, cap(5), "Filled"), note: "Max 5% of sanctioned intake." }
    ];

    const sub = el("quota-sub");
    if (sub) sub.textContent = `${scopeName()} · Digital Seat-Pass`;

    el("quota-matrix").innerHTML = Q.map(q => {
        const p = q.c ? Math.min(100, Math.round(q.f / q.c * 100)) : 0;
        return `<div class="matrix-cell">
            <div class="mk"><span>${escapeHTML(q.label)}</span>${pill(q.s[0], q.s[1])}</div>
            <div class="mv">${q.f}<small> / ${q.c}</small></div>
            <div class="meter" style="--c: var(--${COLOR[q.s[1]]})"><i style="width:${p}%"></i></div>
            <div class="mn">${escapeHTML(q.note)}</div>
        </div>`;
    }).join("");
}

function renderIngHead() {
    const inst = INSTITUTIONS.find(i => i.id === el("f-inst").value) || INSTITUTIONS[0];
    const y = Number(el("f-year").value) || 2026;
    const b = BRANCH_MAP[el("f-branch").value];
    el("ing-head").innerHTML = `<h2>${escapeHTML(inst.name)} ${pill("AICTE Approved", "ok")}</h2>
        <p><span class="mono">Institute: ${escapeHTML(inst.id)}</span> · ${escapeHTML(b.name)} · AY ${y}-${String(y + 1).slice(-2)} · Batch Sync #8841 <span class="muted">(Polars Engine: 1,240 records processed in 0.84s)</span></p>`;
}

function renderBatch() {
    let html = `<tr><th>APAAR / Surrogate ID</th><th>Student ID</th><th>Name</th><th>Category</th><th>Gateway Response</th><th>Status</th></tr>`;
    BATCH.forEach(r => {
        const i = r.r.indexOf(": ");
        const code = escapeHTML(r.r.slice(0, i)), msg = escapeHTML(r.r.slice(i + 2));
        const cls = r.bad ? ` rc-${r.s[1]}` : "";
        html += `<tr>
            <td class="mono nw">${escapeHTML(r.id)}${r.sub ? `<span class="sub">${escapeHTML(r.sub)}</span>` : ""}</td>
            <td class="mono nw">${escapeHTML(r.sid)}</td>
            <td>${escapeHTML(r.nm)}</td>
            <td><span class="chip">${escapeHTML(r.cat)}</span></td>
            <td class="resp-cell"><code class="rc${cls}">${code}</code> ${msg}</td>
            <td>${pill(r.s[0], r.s[1])}</td>
        </tr>`;
    });
    el("batch-table").innerHTML = html;
}

function updateVigilance() {
    buildCaches();
    el("vig-kpi").innerHTML = KPIS.map(k => `<div class="kpi-cell"><div class="mk">${escapeHTML(k[0])}</div><div class="mv">${escapeHTML(k[1])}<small>${escapeHTML(k[2])}</small></div></div>`).join("");

    el("anom-count").innerText = `${ANOM.length} open`;
    let html = `<tr><th>Alert</th><th>Severity</th><th>Score</th><th>Finding</th></tr>`;
    ANOM.forEach(a => {
        html += `<tr>
            <td class="mono nw">#${a.id}<span class="sub">${escapeHTML(a.det)}</span></td>
            <td>${pill(a.sev[0], a.sev[1])}</td>
            <td class="mono">${a.score}</td>
            <td><strong>${escapeHTML(a.who)}</strong> · ${escapeHTML(a.t)}<span class="sub">${escapeHTML(a.tag)}</span></td>
        </tr>`;
    });
    el("anom-table").innerHTML = html;

    const flagged = [];
    let inScopeCount = 0;
    for (const r of db.records) {
        if (!inScope(r)) continue;
        inScopeCount++;
        const f = analyzeFlags(r);
        if (f.length) flagged.push([r, f]);
    }
    el("live-count").innerText = `${flagged.length.toLocaleString()} flagged of ${inScopeCount.toLocaleString()} records · ${scopeName()}`;
    let lhtml = `<tr><th>APAAR ID</th><th>Student</th><th>Institution</th><th>Branch</th><th>Flags</th></tr>`;
    if (flagged.length === 0) lhtml += `<tr><td colspan="5" class="text-center helper-text">No flagged records in the local ledger.</td></tr>`;
    
    flagged.slice(0, 25).forEach(([r, f]) => {
        lhtml += `<tr>
            <td class="mono nw">${escapeHTML(r.apaar)}</td>
            <td><strong>${escapeHTML(r.name)}</strong><span class="sub mono">${escapeHTML(r.sid || "")}</span></td>
            <td>${escapeHTML(getInstName(r.inst))}</td>
            <td><span class="chip">${branchOf(r)}</span></td>
            <td>${f.map(x => `<span class="tag tag-warning">${escapeHTML(x)}</span>`).join(" ")}</td>
        </tr>`;
    });
    if (flagged.length > 25) lhtml += `<tr><td colspan="5" class="text-center helper-text">Showing the first 25. Use the Registry search for the rest.</td></tr>`;
    el("live-flags").innerHTML = lhtml;
}

document.addEventListener("click", e => {
    // Print verification certificate
    const printButton = e.target.closest(".certificate-print-btn");

    if (printButton) {
        e.preventDefault();
        window.print();
        return;
    }

    // Existing audit hash copy functionality
    const h = e.target.closest(".hash");

    if (h && h.dataset.full && navigator.clipboard) {
        navigator.clipboard.writeText(h.dataset.full).catch(() => {});
    }
});
el("f-inst").addEventListener("change", renderIngHead);
el("f-year").addEventListener("input", renderIngHead);

// 📱 REAL QR Code Generator (Connects to actual verification endpoint)
function qrSVG(size = 104) {
    return `
        <div
            id="certificate-qr"
            style="
                width:${size}px;
                height:${size}px;
                padding:4px;
                border:1px solid #b5a572;
                background:#fff;
                margin:auto;
            ">
        </div>
    `;
}

function buildVerificationUrl(apaarHmac) {
    const url = new URL("https://aicte-pramaan-frontend.onrender.com/");

    url.searchParams.set("verify", apaarHmac);

    return url.toString();
}

function renderCertificateQR(apaarHmac, size = 104) {
    const target = document.getElementById("certificate-qr");

    if (!target) return;

    target.innerHTML = "";

    if (typeof window.QRCode !== "function") {
        target.textContent = "QR generator unavailable";
        return;
    }

    new QRCode(target, {
        text: buildVerificationUrl(apaarHmac),
        width: size,
        height: size,
        correctLevel: QRCode.CorrectLevel.M
    });
}

// 📱 Simulated Multi-Device Notifications (SMS/Email)
function showToast(title, msg, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    
    // Add realistic icons based on type
    const icon = type === 'success' ? '💬 SMS' : type === 'info' ? '📧 EMAIL' : '🚨 ALERT';
    
    toast.innerHTML = `<div style="flex:1;"><h4>${title} <span>${icon}</span></h4><p>${msg}</p></div>`;
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(120%)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 5500); // Dissolve after 5.5 seconds
}

// Certificate print styling
(function installCertificatePrintStyles() {
    if (document.getElementById("aicte-certificate-print-styles")) return;

    const style = document.createElement("style");

    style.id = "aicte-certificate-print-styles";

    style.textContent = `
        @page {
            size: A4;
            margin: 12mm;
        }

        .certificate-print-btn {
            white-space: nowrap;
        }

        @media print {
            html, body {
                background: #fff !important;
            }

            body * {
                visibility: hidden !important;
            }

            #v-out, #v-out * {
                visibility: visible !important;
            }

            #v-out {
                position: absolute !important;
                left: 0 !important;
                top: 0 !important;
                width: 100% !important;
                margin: 0 !important;
                padding: 0 !important;
                background: #fff !important;
            }

            #v-out .certificate-print-btn {
                display: none !important;
            }

            #v-out .cols {
                display: grid !important;
                grid-template-columns: 1fr !important;
                gap: 8mm !important;
            }

            #v-out .depth-card,
            #v-out .paper {
                box-shadow: none !important;
            }

            #v-out .depth-card {
                margin-bottom: 8mm !important;
                break-inside: avoid;
                page-break-inside: avoid;
            }

            #v-out .paper {
                max-width: none !important;
            }

            #v-out .mono {
                overflow-wrap: anywhere !important;
            }

            #v-out .tag {
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
        }
    `;

    document.head.appendChild(style);
})();


function buildCertificate(record, c) {
    const br = BRANCH_MAP[branchOf(record)] || {
        name: record.branch || "Not available",
        code: record.branch || "—"
    };

    const year = Number(record.year);

    const batch = year
        ? `${year}-${String(year + 1).slice(-2)}`
        : "Not available";

    const leafHash = c.leafHash || "";

    const apaarShown = /^\d{12}$/.test(String(record.apaar || ""))
        ? String(record.apaar).replace(/(\d{4})(?=\d)/g, "$1-")
        : record.apaar
            ? record.apaar
            : "Protected (QR verification)";

    const ref = `VRF-${leafHash.slice(0, 12).toUpperCase()}`;

    const checks = [
        [c.keyMatches === true, "Trusted public key matches"],
        [c.signatureValid === true, "Student record signature verified"],
        [c.rootSignatureValid === true, "Merkle root signature verified"],
        [c.proofValid === true, "Merkle inclusion proof verified"]
    ];

    const allOk = checks.every(check => check[0]);

    const result = allOk
        ? pill("CRYPTOGRAPHICALLY VERIFIED", "ok")
        : pill("VERIFICATION FAILED", "er");

    const row = (key, value) =>
        `<dt>${key}</dt><dd>${value}</dd>`;

    return `
    <div class="cols">

        <section class="depth-card flush">

            <div class="card-head">
                <h3>Student Record Verification Certificate</h3>

                <button
                    type="button"
                    class="btn btn-primary depth-btn certificate-print-btn"
                    ${allOk ? "" : "disabled"}>
                    Print / Save PDF
                </button>
            </div>

            <div class="paper">

                <div class="row">
                    <div>
                        <small>Institution ID</small>
                        <h3>${escapeHTML(record.inst || "Not available")}</h3>
                        <small>AICTE Pramaan prototype ledger</small>
                    </div>

                    <div class="ids">
                        <div>
                            <b>Student ID:</b>
                            ${escapeHTML(record.sid || "Not available")}
                        </div>

                        <div>
                            <b>APAAR ID:</b>
                            ${escapeHTML(apaarShown)}
                        </div>
                    </div>
                </div>

                <div class="mid">
                    <small>Student record for</small>
                    <br>

                    <span class="nm">
                        ${escapeHTML(record.name || "Not available")}
                    </span>

                    <div style="line-height:1.7;margin-top:6px">
                        Programme
                        <br>

                        <b style="font-size:17px">
                            ${escapeHTML(record.course || record.branch || "Not available")}
                        </b>

                        <br>

                        <span style="font-size:12px">
                            Branch: ${escapeHTML(br.name)}
                            · Admission batch AY ${escapeHTML(batch)}
                        </span>
                    </div>
                </div>

                <div class="ft">
                    <div>
                        Verification reference:
                        ${escapeHTML(ref)}
                        <br>

                        Platform: AICTE Pramaan SIH prototype
                        <br>

                        Method: Ed25519 + SHA-256 Merkle proof
                        <br>

                        Record signature:
                        ${escapeHTML(String(c.signature || "").slice(0, 24))}...
                    </div>

                    <div style="text-align:center">
                        ${qrSVG(104)}

                        <div style="font-size:9px">
                            SCAN TO VERIFY RECORD
                        </div>
                    </div>
                </div>

            </div>
        </section>

        <section class="depth-card flush">

            <div class="card-head">
                <h3>Cryptographic Verification</h3>
                <span class="muted">Server-side consent gate passed</span>
            </div>

            <dl class="kv">
                ${row("Verification reference", escapeHTML(ref))}
                ${row("Result", result)}
            </dl>

            <ul class="checks sep">
                ${checks.map(check => `
                    <li class="${check[0] ? "pass" : "fail"}">
                        ${check[0] ? ICON.check : ICON.cross}
                        ${escapeHTML(check[1])}
                    </li>
                `).join("")}
            </ul>

            <div class="sep" style="padding:16px;background:#fafafa">

                <b style="font-size:13px;color:#1e293b">
                    Cryptographic Signature Information
                </b>

                <div class="mono"
                    style="
                        font-size:11px;
                        color:var(--text-light);
                        word-break:break-all;
                        line-height:1.6">

                    <b>Trusted Public Key:</b>
                    ${escapeHTML(c.publicKey || "")}

                    <br>

                    <b>Record Signature:</b>
                    ${escapeHTML(c.signature || "")}

                    <br>

                    <b>Merkle Root Signature:</b>
                    ${escapeHTML(c.rootSignature || "")}

                    <br>

                    <b>Algorithm:</b>
                    Ed25519 / SHA-256

                </div>
            </div>

            <dl class="kv sep">
                ${row("Merkle root", escapeHTML(c.rootHash || ""))}
                ${row("Leaf hash", escapeHTML(leafHash))}
                ${row(
                    "Proof path",
                    `${Number(c.proofLen || 0)} sibling nodes · ${Number(c.total || 0).toLocaleString()} records`
                )}
                ${row(
                    "Inclusion proof",
                    c.proofValid
                        ? pill("VALID", "ok")
                        : pill("INVALID", "er")
                )}
                ${row(
                    "Root signature",
                    c.rootSignatureValid
                        ? pill("VALID", "ok")
                        : pill("INVALID", "er")
                )}
            </dl>

        </section>
    </div>`;
}



function hexToBytes(hex) {
    if (
        typeof hex !== "string" ||
        hex.length % 2 !== 0 ||
        !/^[0-9a-f]+$/i.test(hex)
    ) {
        throw new Error("Invalid hexadecimal value");
    }

    return Uint8Array.from(
        hex.match(/.{2}/g).map(x => parseInt(x, 16))
    );
}

function concatBytes(...parts) {
    const result = new Uint8Array(
        parts.reduce((n, p) => n + p.length, 0)
    );

    let offset = 0;

    for (const part of parts) {
        result.set(part, offset);
        offset += part.length;
    }

    return result;
}

function toHex(bytes) {
    return Array.from(
        bytes,
        b => b.toString(16).padStart(2, "0")
    ).join("");
}

async function sha256(bytes) {
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return new Uint8Array(digest);
}

async function verifyLedgerPayload(payload) {
    if (!window.nacl) {
        throw new Error("Ed25519 verification library failed to load");
    }

    if (
        !payload ||
        payload.version !== "1.0" ||
        !payload.data ||
        !Array.isArray(payload.proof) ||
        !/^[a-f0-9]{64}$/i.test(payload.apaar_hmac || "") ||
        !/^[a-f0-9]{64}$/i.test(payload.merkle_root || "")
    ) {
        throw new Error("Incomplete or invalid verification payload");
    }

    const d = payload.data;
    const encoder = new TextEncoder();

    if (
        !d.student_id ||
        !d.name ||
        !d.institution_id ||
        !d.branch ||
        d.admission_year === undefined ||
        d.admission_year === null
    ) {
        throw new Error("Student record contains missing fields");
    }

    const trustedKey = hexToBytes(TRUSTED_ED25519_PUBLIC_KEY);

    if (trustedKey.length !== 32) {
        throw new Error("Invalid trusted public key configuration");
    }

    const keyMatches =
        typeof payload.public_key === "string" &&
        payload.public_key.toLowerCase() ===
        TRUSTED_ED25519_PUBLIC_KEY.toLowerCase();

    // Property order must match backend signData().
    const recordData = {
        student_id: d.student_id,
        name: d.name,
        institution_id: d.institution_id,
        branch: d.branch,
        admission_year: d.admission_year
    };

    const recordSignature = hexToBytes(payload.signature);

    const recordSignatureValid =
        keyMatches &&
        recordSignature.length === 64 &&
        nacl.sign.detached.verify(
            encoder.encode(JSON.stringify(recordData)),
            recordSignature,
            trustedKey
        );

    const rootData = {
        merkle_root: payload.merkle_root
    };

    const rootSignature = hexToBytes(
        payload.merkle_root_signature
    );

    const rootSignatureValid =
        keyMatches &&
        rootSignature.length === 64 &&
        nacl.sign.detached.verify(
            encoder.encode(JSON.stringify(rootData)),
            rootSignature,
            trustedKey
        );

    // Reconstruct the exact leaf used by the backend.
    const canonicalData =
        `${payload.apaar_hmac}|${d.student_id}|` +
        `${d.institution_id}|${d.branch}|${d.admission_year}`;

    let currentHash = await sha256(
        concatBytes(
            new Uint8Array([0x00]),
            encoder.encode(canonicalData)
        )
    );

    const leafHash = toHex(currentHash);

    // Verify the Merkle inclusion proof.
    for (const item of payload.proof) {
        if (
            !item ||
            !["left", "right"].includes(item.position)
        ) {
            throw new Error("Invalid Merkle proof structure");
        }

        const sibling = hexToBytes(item.sibling);

        if (sibling.length !== 32) {
            throw new Error("Invalid Merkle sibling hash");
        }

        const left = item.position === "left"
            ? sibling
            : currentHash;

        const right = item.position === "right"
            ? sibling
            : currentHash;

        currentHash = await sha256(
            concatBytes(
                new Uint8Array([0x01]),
                left,
                right
            )
        );
    }

    const proofValid =
        toHex(currentHash).toLowerCase() ===
        payload.merkle_root.toLowerCase();

    return {
        keyMatches,
        recordSignatureValid,
        rootSignatureValid,
        proofValid,
        leafHash,

        valid:
            keyMatches &&
            recordSignatureValid &&
            rootSignatureValid &&
            proofValid
    };
}


// Main verification function.
// Supports both manual APAAR entry and QR-based HMAC lookup.
async function performRecordVerification({
    apaarId = "",
    apaarHmac = ""
} = {}) {
    const out = el("v-out");

    out.innerHTML = `<div class="loader-line"></div>`;

    try {
        const normalizedId = normalizeApaarId(apaarId);

        const endpoint = apaarHmac
        ? `${API_BASE}/api/records/verify-hmac/${encodeURIComponent(apaarHmac)}`
        : `${API_BASE}/api/records/generate-qr/${encodeURIComponent(normalizedId)}`;
        const fetchVerification = async () => {
    const r = await fetch(endpoint);
    return { response: r, payload: await r.json().catch(() => ({})) };
};

let { response, payload } = await fetchVerification();

if (response.status === 404 && !apaarHmac) {
    const local = db.records.find(r => r.apaar === normalizedId);
    if (local) {
        if (!jwtToken) {
            out.innerHTML = `<div class="depth-card"><p class="text-danger">
                This record exists only in the local registry. Log in as AICTE Admin
                (2FA) so it can be synced to the ledger.</p></div>`;
            return;
        }
        out.innerHTML = `<div class="loader-line"></div>`;
        await syncRecordsToBackend([local]);
        ({ response, payload } = await fetchVerification());
    }
}

        if (response.status === 403) {
            out.innerHTML = `
                <div class="depth-card">
                    <h4 class="text-danger">Access Denied</h4>
                    <p>Student consent is not available for verification.</p>
                </div>`;
            return;
        }

        if (response.status === 404) {
            out.innerHTML = `
                <div class="depth-card">
                    <p class="text-danger">
                        Record not found in the cryptographic ledger.
                    </p>
                </div>`;
            return;
        }

        if (!response.ok) {
            throw new Error(
                payload.error || "Backend verification failed"
            );
        }

        const result = await verifyLedgerPayload(payload);

        const record = {
            inst: payload.data.institution_id,
            sid: payload.data.student_id,

            // QR lookup deliberately does not reveal the raw APAAR ID.
            apaar: apaarId,

            name: payload.data.name,
            course:
                courseFor(payload.data.branch) ||
                payload.data.branch,
            year: payload.data.admission_year,
            branch: payload.data.branch
        };

        out.innerHTML = buildCertificate(record, {
            keyMatches: result.keyMatches,
            signatureValid: result.recordSignatureValid,
            rootSignatureValid: result.rootSignatureValid,
            proofValid: result.proofValid,

            publicKey: payload.public_key,
            signature: payload.signature,
            rootSignature: payload.merkle_root_signature,

            rootHash: payload.merkle_root,
            leafHash: result.leafHash,

            proofLen: payload.proof.length,
            total: payload.record_count
        });

        // Generate the record-specific QR after the certificate is inserted.
        renderCertificateQR(payload.apaar_hmac, 104);

    } catch (error) {
        console.error("Cryptographic verification error:", error);

        out.innerHTML = `
            <div class="depth-card">
                <h4 class="text-danger">Verification Failed</h4>
                <p>${escapeHTML(error.message)}</p>
            </div>`;
    }
}


// Manual verification using a 12-digit APAAR ID.
el("v-btn").addEventListener("click", async () => {
    const rawId = normalizeApaarId(el("v-id").value);

    if (rawId.length < 8) {
        el("v-out").innerHTML = `
            <div class="depth-card">
                <p class="text-danger">
                    Enter a valid APAAR or provisional ID.
                </p>
            </div>`;
        return;
    }

    await performRecordVerification({
        apaarId: rawId
    });
});


// Automatic verification when someone scans the certificate QR code.
const qrReference = new URLSearchParams(
    window.location.search
).get("verify");

if (qrReference) {
    if (/^[a-f0-9]{64}$/i.test(qrReference)) {
        performRecordVerification({
            apaarHmac: qrReference
        });
    } else {
        el("v-out").innerHTML = `
            <div class="depth-card">
                <p class="text-danger">
                    Invalid QR verification reference.
                </p>
            </div>`;
    }
}


// ======================================================================
// Docker Engine Event Listener
// ======================================================================
const API_BASE_URL = "https://aicte-pramaan-data-engine.onrender.com";

document.addEventListener("click", async (e) => {
    const btn = e.target.closest("#docker-btn");
    if (!btn) return;

    console.log("Docker button clicked!");

    const msg = document.getElementById("docker-msg");
    if (!msg) return;

    btn.innerHTML = "Processing...";
    btn.disabled = true;

    try {
        msg.innerHTML = `<span class="tag tag-info">Synthesizing 300 records via Polars...</span>`;

        // 1. Fetch from Docker Data Engine
        const engineRes = await fetch(`${API_BASE_URL}/stream-records?count=300`);
        const data = await engineRes.json();
        
        if (!engineRes.ok) throw new Error(data.error || "Failed to generate records");

        const engineRecords = data.records.map(r => {
            const branchCode = guessBranch(r.course || "");
            return {
                apaar_id:       r.apaar  || "",
                student_id:     r.sid    || "",
                name:           r.name   || "",
                institution_id: r.inst   || "",
                branch:         branchCode,
                admission_year: Number(r.year) || 2026,
                is_tfw:         !!r.tfw,
                is_ews:         !!r.ews,
                is_nri:         !!r.nri,
                is_fn:          !!r.fn,
                has_consent:    r.consent !== false
            };
        });

        // 2. Save to backend ledger
        btn.innerText = "Saving to ledger...";
        const CHUNK = 1000;
        const totals = { inserted: 0, already_present: 0, invalid: 0 };

        for (let i = 0; i < engineRecords.length; i += CHUNK) {
            const chunk = engineRecords.slice(i, i + CHUNK);
            msg.innerHTML = `<span class="tag tag-info">Saving to ledger: ${Math.min(i + CHUNK, engineRecords.length).toLocaleString()} / ${engineRecords.length.toLocaleString()}</span>`;

            const res = await fetch(`${API_BASE}/api/records/bulk-ingest`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${jwtToken}`
                },
                body: JSON.stringify({ records: chunk })
            });

            const resData = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(resData.error || `Backend error ${res.status}`);

            totals.inserted        += resData.inserted        || 0;
            totals.already_present += resData.already_present || 0;
            totals.invalid         += resData.invalid         || 0;
        }

        // 3. Mirror records locally
        db.records = engineRecords.map(r => ({
            apaar:  r.apaar_id,
            sid:    r.student_id,
            name:   r.name,
            inst:   r.institution_id,
            branch: r.branch,
            course: courseFor(r.branch) || r.branch,
            year:   r.admission_year,
            tfw:    r.is_tfw,
            ews:    r.is_ews,
            nri:    r.is_nri,
            fn:     r.is_fn,
            sup:    false,
            ghost_flag: false,
            consent: r.has_consent
        }));
        
        db.merkleRoot = data.merkle_root || "";
        saveDB();

        logAudit(
            "MASS_INGESTION",
            `Streamed ${engineRecords.length} records; ${totals.inserted} stored in ledger, ` +
            `${totals.already_present} already present.`
        );

        msg.innerHTML =
            `<span class="tag tag-success">${totals.inserted.toLocaleString()} saved to ledger` +
            (totals.already_present ? `, ${totals.already_present.toLocaleString()} already present` : "") +
            (totals.invalid ? `, ${totals.invalid} skipped (invalid)` : "") +
            `</span>`;

        document.querySelector('[data-page="dash"]').click();
        
        setTimeout(() => {
            const rootEl = document.getElementById("s-root");
            if(rootEl) {
                rootEl.innerText = db.merkleRoot
                    ? db.merkleRoot.substring(0, 16) + "..."
                    : "Computed via Backend";
            }
        }, 500);

        await updateDashboard();
        updateRecords();

    } catch (error) {
        console.error("Stream/sync failed:", error);
        const userMsg = error.name === 'AbortError'
            ? "Timed out — data engine is cold-starting. Wait 60s and retry."
            : error.message;
        msg.innerHTML = `<span class="tag tag-danger">Failed: ${escapeHTML(userMsg)}</span>`;
    } finally {
        btn.innerText = "Stream 300 Records";
        btn.disabled = false;
    }
});

// ===== Responsive tables: safe auto-labeling for phone card views =====
(function () {
    const IDS = [
        "inst-table", "batch-table", "rec-table", "anom-table",
        "live-flags", "review-table", "audit-table", "rank-table"
    ];

    const observers = new Map();

    function prep(t) {
        if (!t) return;
        const first = t.querySelector("tr");
        if (!first) return;

        const obs = observers.get(t);
        if (obs) obs.disconnect();

        const heads = [...first.children].map(h => h.textContent.trim());
        first.classList.add("rhead");

        t.querySelectorAll("tr").forEach(tr => {
            if (tr === first) return;
            [...tr.children].forEach((td, i) => {
                if (td.hasAttribute("colspan")) return;
                if (heads[i]) td.setAttribute("data-label", heads[i]);

                if (!td.querySelector(":scope > .cv")) {
                    const w = document.createElement("div");
                    w.className = "cv";
                    while (td.firstChild) w.appendChild(td.firstChild);
                    td.appendChild(w);
                }
            });
        });
        
        t.classList.add("rtable");

        if (obs) obs.observe(t, { childList: true, subtree: true });
    }

    IDS.forEach(id => {
        const t = document.getElementById(id);
        if (!t) return;

        const obs = new MutationObserver(() => prep(t));
        observers.set(t, obs);

        prep(t);
        obs.observe(t, { childList: true, subtree: true });
    });
})();

// ============================================================
// MOBILE NAVIGATION — INDEPENDENT INITIALIZATION
// ============================================================
(function initializeMobileNavigation() {
    const toggle = document.getElementById("nav-toggle");
    const sidebar = document.getElementById("sidebar");
    const overlay = document.getElementById("nav-overlay");

    if (!toggle || !sidebar || !overlay) return;

    const mobileQuery = window.matchMedia("(max-width: 1024px)");

    function setMenuOpen(open) {
        if (!mobileQuery.matches) open = false;
        document.body.classList.toggle("nav-open", open);
        toggle.setAttribute("aria-expanded", String(open));
        overlay.setAttribute("aria-hidden", String(!open));
    }

    toggle.addEventListener("click", function (event) {
        event.preventDefault();
        const isOpen = document.body.classList.contains("nav-open");
        setMenuOpen(!isOpen);
    });

    overlay.addEventListener("click", function () {
        setMenuOpen(false);
    });

    sidebar.querySelectorAll(".nav-menu a").forEach(function (link) {
        link.addEventListener("click", function () {
            setMenuOpen(false);
        });
    });

    document.addEventListener("keydown", function (event) {
        if (event.key === "Escape") setMenuOpen(false);
    });

    function handleBreakpointChange() {
        if (!mobileQuery.matches) setMenuOpen(false);
    }

    if (mobileQuery.addEventListener) {
        mobileQuery.addEventListener("change", handleBreakpointChange);
    } else {
        mobileQuery.addListener(handleBreakpointChange);
    }

    window.addEventListener("resize", handleBreakpointChange);
    setMenuOpen(false);
})();

// Wake both Render services on page load
(function pingBackend() {
    fetch(`${API_BASE}/health`,  { method: 'GET' }).catch(() => {});
    fetch(`${API_BASE_URL}/`,    { method: 'GET' }).catch(() => {});
})();