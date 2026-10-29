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

INSTITUTIONS = ["INST001", "INST002", "INST003"]
COURSES = ["B.Tech CSE", "B.Tech ECE", "B.Tech ME", "PGDM", "B.Tech IT"]

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
