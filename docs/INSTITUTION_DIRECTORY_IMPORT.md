# Institution directory import

The API and frontend use a MongoDB-backed institution directory. The repository seeds the three existing INST00x demo institutions, all 138 institutions in JoSAA's 2026–27 participating-institute directory, and RGIPT as a separately sourced entry. This starter catalogue is not a complete list of every AICTE-approved technical institution in India.

## Official source scope

JoSAA's 2026–27 participating-institute directory lists 138 institutes: 23 IITs, IISc, 31 NITs, IIEST, 26 IIITs and 56 Other-GFTIs. The institute codes used in this seed are the codes shown in the official directory:

https://josaa.admissions.nic.in/applicant/seatmatrix/instituteview.aspx

RGIPT is listed separately from JoSAA because it is not part of that 138-institute JoSAA count. Its official website is:

https://www.rgipt.ac.in/

The JoSAA directory is not a complete list of every AICTE-approved college in India. For broader coverage, import the current official AICTE-approved-institute or AISHE dataset separately. Do not label an institute AICTE approved solely because it appears in the JoSAA or RGIPT source.

## CSV format

Use institutions-template.csv as the header and format example. Required columns:

- institution_id: stable application ID. For JoSAA entries, use JOSAA- followed by the institute code.
- name: official institute name.
- category: IIT, IISC, NIT, IIEST, IIIT, GFTI, RGIPT, AICTE_APPROVED, STATE or OTHER.

Optional columns: josaa_code, short_name, state, city, website, source, source_url, source_year, verification_status, aliases.

Aliases may be separated with a vertical bar. Quote CSV cells that contain commas.

Allowed verification statuses: source_listed, official_site_listed, pending_review, demo.

## Import from Kali

1. Download or prepare a CSV from the official source.
2. Save it locally, for example as backend/data/institutions.csv.
3. Keep the CSV out of git if it contains personal contacts or other unnecessary data.
4. Configure the backend MONGO_URI in backend/.env.
5. Run the following commands:

   cd backend
   npm install
   npm run import:institutions -- data/institutions.csv

6. Restart the backend. The frontend retrieves active directory items from GET /api/institutions.

The Data Engine's default synthetic-data pool contains the seeded institution IDs. If you import additional institutions and want synthetic data to include them, set the Data Engine environment variable `INSTITUTION_IDS` to a comma-separated list of active institution IDs.

The CLI importer uses MongoDB directly. The API also exposes POST /api/institutions/bulk-import, which requires the AICTE role.

## Data safety

- This feature does not create login accounts for every institution.
- The current login route still has demonstration-only users and a fixed demo OTP. Do not use it for real college accounts or real student data.
- Seat and intake values are not invented for newly imported institutions. The quota dashboard will display Not configured until a verified seat matrix is provided.
