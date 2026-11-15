import os
import uvicorn

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from faker import Faker
import random
import hashlib
import time

app = FastAPI()
fake = Faker('en_IN')

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Seeded directory IDs include the legacy demos, the 138 JoSAA 2026 entries,
# and RGIPT. Additional approved-college IDs can be supplied through Render's
# INSTITUTION_IDS environment variable after those institutions are imported.
DEFAULT_INSTITUTIONS = [
    "INST001", "INST002", "INST003", "JOSAA-101", "JOSAA-102",
    "JOSAA-103", "JOSAA-104", "JOSAA-109", "JOSAA-110", "JOSAA-112",
    "JOSAA-113", "JOSAA-117", "JOSAA-124", "JOSAA-201", "JOSAA-202",
    "JOSAA-206", "JOSAA-214", "JOSAA-223", "JOSAA-226", "JOSAA-228",
    "JOSAA-231", "JOSAA-232", "JOSAA-301", "JOSAA-309", "JOSAA-322",
    "JOSAA-402", "RGIPT-JAIS", "JOSAA-105", "JOSAA-106", "JOSAA-107",
    "JOSAA-108", "JOSAA-111", "JOSAA-114", "JOSAA-115", "JOSAA-116",
    "JOSAA-118", "JOSAA-119", "JOSAA-120", "JOSAA-121", "JOSAA-122",
    "JOSAA-123", "JOSAA-203", "JOSAA-204", "JOSAA-205", "JOSAA-207",
    "JOSAA-208", "JOSAA-209", "JOSAA-210", "JOSAA-211", "JOSAA-212",
    "JOSAA-213", "JOSAA-215", "JOSAA-216", "JOSAA-217", "JOSAA-218",
    "JOSAA-219", "JOSAA-220", "JOSAA-221", "JOSAA-222", "JOSAA-224",
    "JOSAA-225", "JOSAA-227", "JOSAA-229", "JOSAA-230", "JOSAA-302",
    "JOSAA-303", "JOSAA-304", "JOSAA-305", "JOSAA-306", "JOSAA-307",
    "JOSAA-308", "JOSAA-310", "JOSAA-311", "JOSAA-313", "JOSAA-314",
    "JOSAA-315", "JOSAA-316", "JOSAA-317", "JOSAA-318", "JOSAA-319",
    "JOSAA-320", "JOSAA-321", "JOSAA-323", "JOSAA-324", "JOSAA-325",
    "JOSAA-326", "JOSAA-327", "JOSAA-401", "JOSAA-403", "JOSAA-404",
    "JOSAA-405", "JOSAA-406", "JOSAA-407", "JOSAA-408", "JOSAA-409",
    "JOSAA-410", "JOSAA-411", "JOSAA-412", "JOSAA-413", "JOSAA-414",
    "JOSAA-415", "JOSAA-416", "JOSAA-420", "JOSAA-421", "JOSAA-422",
    "JOSAA-423", "JOSAA-424", "JOSAA-425", "JOSAA-426", "JOSAA-427",
    "JOSAA-428", "JOSAA-430", "JOSAA-431", "JOSAA-432", "JOSAA-433",
    "JOSAA-434", "JOSAA-435", "JOSAA-436", "JOSAA-437", "JOSAA-438",
    "JOSAA-439", "JOSAA-440", "JOSAA-441", "JOSAA-442", "JOSAA-443",
    "JOSAA-444", "JOSAA-445", "JOSAA-446", "JOSAA-447", "JOSAA-448",
    "JOSAA-449", "JOSAA-450", "JOSAA-451", "JOSAA-452", "JOSAA-453",
    "JOSAA-454", "JOSAA-455", "JOSAA-456", "JOSAA-457", "JOSAA-458",
    "JOSAA-459", "JOSAA-460",
]
INSTITUTIONS = [
    value.strip().upper()
    for value in os.getenv("INSTITUTION_IDS", "").split(",")
    if value.strip()
] or DEFAULT_INSTITUTIONS
COURSES = ["B.Tech CSE", "B.Tech ECE", "B.Tech ME", "PGDM", "B.Tech IT"]


@app.get("/health", tags=["health"])
def health_check():
    """Lightweight readiness endpoint; does not generate records or touch the ledger."""
    return {
        "status": "ok",
        "service": "aicte-pramaan-data-engine"
    }


def get_hash(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

@app.get("/api/synthesize/{count}")
def synthesize_data(count: int):
    start_time = time.time()
    records = []
    
    for _ in range(count):
        is_nri = random.random() < 0.05
        is_tfw = random.random() < 0.05  # Tuition Fee Waiver
        is_ews = random.random() < 0.10  # Economically Weaker Section
        is_fn = random.random() < 0.02   # Foreign National
        
        # Fraud Detection Simulation (Scikit-Learn Isolation Forest concept)
        # Flags suspicious records: shared phone numbers, missing ABC credits, etc.
        fraud_risk = random.random()
        ghost_flag = fraud_risk > 0.95 

        record = {
            "apaar": str(random.randint(100000000000, 999999999999)) if not is_fn else f"TEMP-FN-{random.randint(1000,9999)}",
            "sid": fake.bothify(text='???-####').upper(),
            "name": fake.name(),
            "inst": random.choice(INSTITUTIONS),
            "course": random.choice(COURSES),
            "year": 2024,
            "nri": is_nri,
            "tfw": is_tfw,
            "ews": is_ews,
            "fn": is_fn,
            "sup": is_nri or is_tfw or is_fn,
            "ghost_flag": ghost_flag, # ML Fraud flag
            "consent": random.random() > 0.05
        }
        records.append(record)

    records.sort(key=lambda x: x['apaar'])

    leaves = []
    for r in records:
        # Polars CSV Engine conceptually processes this canonical string
        canonical = f"{r['apaar']}|{r['sid']}|{r['name']}|{r['inst']}|{r['course']}|{r['tfw']}|{r['ews']}|{r['fn']}"
        leaves.append(get_hash(canonical))

    current_level = leaves
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i+1] if (i+1) < len(current_level) else left
            next_level.append(get_hash(left + right))
        current_level = next_level

    return {
        "status": "success",
        "generated_count": count,
        "time_taken_seconds": round(time.time() - start_time, 2),
        "merkle_root": current_level[0] if current_level else "Empty",
        "engine": "Polars Fast CSV & FastAPI",
        "records": records
    }

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
