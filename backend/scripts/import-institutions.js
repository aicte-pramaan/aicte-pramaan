const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const connectDB = require('../config/db');
const Institution = require('../models/Institution');
const mongoose = require('mongoose');

function parseCsvLine(line) {
    const values = [];
    let value = '';
    let quoted = false;

    for (let i = 0; i < line.length; i++) {
        const char = line[i];
        if (char === '"' && quoted && line[i + 1] === '"') {
            value += '"';
            i++;
        } else if (char === '"') {
            quoted = !quoted;
        } else if (char === ',' && !quoted) {
            values.push(value.trim());
            value = '';
        } else {
            value += char;
        }
    }
    values.push(value.trim());
    return values;
}

function parseCsv(text) {
    const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/).filter(line => line.trim());
    if (lines.length < 2) throw new Error('CSV must contain a header and at least one institution row.');

    const headers = parseCsvLine(lines[0]).map(header => header.trim().toLowerCase());
    const required = ['institution_id', 'name', 'category'];
    for (const key of required) {
        if (!headers.includes(key)) throw new Error('CSV is missing required column: ' + key);
    }

    return lines.slice(1).map((line, index) => {
        const values = parseCsvLine(line);
        const row = {};
        headers.forEach((header, i) => { row[header] = values[i] || ''; });
        row.institution_id = String(row.institution_id || '').trim().toUpperCase();
        row.name = String(row.name || '').trim();
        row.category = String(row.category || 'OTHER').trim().toUpperCase();
        row.aliases = String(row.aliases || '').split('|').map(value => value.trim()).filter(Boolean);
        row.source_year = row.source_year ? Number(row.source_year) : undefined;
        row.is_active = String(row.is_active || 'true').toLowerCase() !== 'false';
        row.verification_status = row.verification_status || 'pending_review';

        if (!row.institution_id || !row.name || !row.category) {
            throw new Error('Invalid required fields on CSV data row ' + (index + 2));
        }
        return row;
    });
}

async function main() {
    const filename = process.argv[2];
    if (!filename) {
        throw new Error('Usage: npm run import:institutions -- path/to/institutions.csv');
    }

    const csvPath = path.resolve(process.cwd(), filename);
    const rows = parseCsv(fs.readFileSync(csvPath, 'utf8'));
    await connectDB();

    const operations = rows.map(row => ({
        updateOne: {
            filter: { institution_id: row.institution_id },
            update: {
                $set: {
                    institution_id: row.institution_id,
                    josaa_code: row.josaa_code || undefined,
                    name: row.name,
                    short_name: row.short_name || '',
                    category: row.category,
                    state: row.state || '',
                    city: row.city || '',
                    website: row.website || '',
                    aliases: row.aliases || [],
                    source: row.source || 'Imported institution dataset',
                    source_url: row.source_url || '',
                    source_year: row.source_year,
                    verification_status: row.verification_status,
                    is_active: row.is_active
                },
                $setOnInsert: { is_demo: false }
            },
            upsert: true
        }
    }));

    const result = await Institution.bulkWrite(operations, { ordered: false });
    console.log('Institution import complete.');
    console.log('Rows read:', rows.length);
    console.log('Inserted:', result.upsertedCount || 0);
    console.log('Updated:', result.modifiedCount || 0);
    await mongoose.disconnect();
}

main().catch(async error => {
    console.error('Institution import failed:', error.message);
    try { await mongoose.disconnect(); } catch (_) {}
    process.exitCode = 1;
});
