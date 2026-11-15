const Institution = require('../models/Institution');
const seed = require('../data/institutions-seed.json');

async function seedInstitutions() {
    if (!Array.isArray(seed) || seed.length === 0) return;

    const operations = seed.map(item => ({
        updateOne: {
            filter: { institution_id: item.institution_id },
            update: { $setOnInsert: item },
            upsert: true
        }
    }));

    const result = await Institution.bulkWrite(operations, { ordered: false });
    console.log(
        'Institution directory ready:',
        result.upsertedCount || 0,
        'seed entries added; existing entries preserved.'
    );
}

module.exports = seedInstitutions;
