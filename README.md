# CVE Vulnerability Analysis System

Real-time CVE severity prediction and vulnerability classification using fine-tuned RoBERTa and DistilBERT models.

## Features
- **2-Model Ensemble**: RoBERTa (severity classification) + DistilBERT (vulnerability type classification).
- **High Performance**: <500ms single prediction latency (p99) on CPU, much faster on GPU.
- **Offline / Air-Gapped Capable**: Self-contained SQLite database and local caching of tokenizers and model weights.
- **Auditable**: All API predictions and retraining sessions are logged directly to the local SQLite database for model drift monitoring and retraining.
- **Async Retraining**: Asynchronous background retraining pipeline that logs parameters and metrics to `cve.db`.
- **Fast Startup**: Bootstrapping scripts support quick mock models/weights generation to test end-to-end routing without downloading 800MB+ models.

## Directory Structure
```text
cve-vulnerability-system/
├── backend/
│   ├── main.py            # FastAPI main application
│   ├── config.py          # Configuration management via Pydantic Settings
│   ├── api/
│   │   ├── routes.py      # Severity, classify, batch, and DB endpoints
│   │   └── schemas.py     # Pydantic validation schemas
│   ├── database/
│   │   ├── schema.py      # SQLite table initialization script
│   │   └── crud.py        # Database operations
│   ├── models/
│   │   └── inference.py   # Two-model inference caching engine
│   └── training/
│       ├── train_roberta.py    # Severity fine-tuning training script
│       └── train_distilbert.py # Type fine-tuning training script
├── data/
│   ├── raw/               # Raw datasets (e.g. nvd_cves.csv)
│   ├── processed/         # Train, validation, and test splits
│   └── cve.db             # Local SQLite database (created at runtime)
├── docker/
│   └── Dockerfile         # Multi-stage production container definition
├── docs/                  # API, Architecture, and Deployment docs
├── models/                # Local cache directory for model weights
├── scripts/
│   ├── bootstrap_models.py # Downloads configs and tokenizers
│   └── load_data.py       # Data pipeline (generates 8500+ synthetic CVEs if missing)
├── tests/
│   └── test_api.py        # API and latency test suite
├── requirements.txt       # Dependencies
└── .env                   # Local configurations
```

## Quick Start

### 1. Setup Virtual Environment
```bash
python -m venv venv
# Windows:
.\venv\Scripts\Activate.ps1
# macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Ingest Data and Setup Database
Run the data pipeline to initialize the database schema, generate a synthetic dataset of 8,500 records (if raw CSV is not present), and create the train/val/test splits:
```bash
python scripts/load_data.py
```

### 3. Bootstrap Local Model Cache
To run the server offline, cache the tokenizers and configurations locally. Use `--random-weights` for an instant startup (under 10 seconds, skips downloading 800MB model weights):
```bash
python scripts/bootstrap_models.py --random-weights
```
*Note: To download actual pre-trained weights from Hugging Face, omit the `--random-weights` flag.*

### 4. Run the Application
Start the FastAPI server:
```bash
python backend/main.py
```
Open **[http://localhost:8000/docs](http://localhost:8000/docs)** to view the Swagger API documentation.

## API Endpoints

### 1. Predict Severity
- **Endpoint**: `POST /api/v1/predict/severity`
- **Payload**:
  ```json
  {
    "cve_id": "CVE-2023-1234",
    "cve_description": "SQL injection vulnerability in the login module allows remote attackers to execute arbitrary queries."
  }
  ```
- **Response**:
  ```json
  {
    "cve_id": "CVE-2023-1234",
    "severity": "High",
    "confidence": 0.8872,
    "inference_time_ms": 42.15
  }
  ```

### 2. Predict Vulnerability Type
- **Endpoint**: `POST /api/v1/predict/classify`
- **Payload**:
  ```json
  {
    "cve_id": "CVE-2023-1234",
    "cve_description": "Cross-site scripting (XSS) vulnerability in comments section allows cookie hijacking."
  }
  ```
- **Response**:
  ```json
  {
    "cve_id": "CVE-2023-1234",
    "vulnerability_type": "XSS",
    "confidence": 0.9521,
    "inference_time_ms": 35.8
  }
  ```

### 3. Batch Predictions (Max 100)
- **Endpoint**: `POST /api/v1/predict/batch`
- **Payload**:
  ```json
  {
    "descriptions": [
      { "cve_id": "CVE-2023-0001", "description": "SQL injection in search bar" },
      { "cve_id": "CVE-2023-0002", "description": "Buffer overflow in image parser allows arbitrary code execution" }
    ]
  }
  ```

### 4. Retrieve Recent Predictions
- **Endpoint**: `GET /api/v1/vulnerabilities`
- **Query Params**: `limit` (default 100), `severity` (optional filter)

## Running Tests
Run the pytest suite to verify all APIs, latencies, and SQLite logging:
```bash
pytest tests/test_api.py -v
```

## Production Deployment (Docker)
Build and run the container:
```bash
docker build -f docker/Dockerfile -t cve-system .
docker run -p 8000:8000 cve-system
```
