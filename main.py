import os
import uvicorn
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re
import time

# Import our ML and DB components from cve_pipeline
from cve_pipeline import (
    CVEDatabase,
    CVEModelEngine,
    fetch_single_cve_nvd,
    preprocess_text,
    extract_exploit_type,
    extract_component,
    extract_impact,
    cvss_to_severity,
    MODELS_DIR
)

# ==============================================================================
# 1. SETUP & INITIALIZATION
# ==============================================================================

app = FastAPI(
    title="Cyber Threat Intelligence Dashboard",
    description="Professional CVE NLP Trend Analysis and Threat Forecasting Engine",
    version="1.0.0"
)

# Enable CORS for easy local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database and train engine
db = CVEDatabase()
ml_engine = CVEModelEngine(db)

# Create static folder structures if not exist
os.makedirs("static/css", exist_ok=True)
os.makedirs("static/js", exist_ok=True)

# ==============================================================================
# 2. SCHEMAS
# ==============================================================================

class CVEInput(BaseModel):
    cve_id: str

class MEMMForecastInput(BaseModel):
    next_cvss: float

class BulkImportInput(BaseModel):
    cve_ids: list[str]

# ==============================================================================
# 3. BACKGROUND TASKS
# ==============================================================================

def process_bulk_cves(cve_ids: list[str]):
    """Background task to fetch and save multiple CVEs with rate limit cushioning."""
    print(f"[Background] Starting background bulk fetch for {len(cve_ids)} CVEs...")
    for cve_id in cve_ids:
        cve_id = cve_id.strip().upper()
        try:
            # Check if already in db to avoid redundant network hits
            existing, _ = db.fetch_all(limit=1, search=cve_id)
            if existing:
                print(f"   * {cve_id} already exists in DB. Skipping.")
                continue

            # Fetch
            record = fetch_single_cve_nvd(cve_id)
            if record:
                # Process
                cleaned_desc = preprocess_text(record['Description'])
                exploit = extract_exploit_type(record['Description'])
                component = extract_component(record['Description'])
                impact = extract_impact(record['Description'])
                true_sev = cvss_to_severity(record['CVSS_Score'])
                
                # Model Prediction
                pred_cvss = ml_engine.predict_cvss_score(record['Description'])
                pred_sev = cvss_to_severity(pred_cvss)
                
                # Confidence indicator
                confidence = 1.0 - min(0.4, abs(record['CVSS_Score'] - pred_cvss) / 10.0)

                # BERT predictions (lazy-loaded, won't slow down startup)
                bert_cat, bert_conf = 'N/A', 0.0
                try:
                    bert_cat, bert_conf = ml_engine.predict_category_bert(record['Description'])
                except Exception as bert_err:
                    print(f"   [!] BERT category prediction skipped: {bert_err}")

                db.save_cve({
                    'CVE_ID': record['CVE_ID'],
                    'Description': record['Description'],
                    'Cleaned_Description': cleaned_desc,
                    'Year': record['Year'],
                    'CVSS_Score': record['CVSS_Score'],
                    'CWE': record['CWE'],
                    'OS': record['OS'],
                    'Exploit_Type': exploit,
                    'Affected_Component': component,
                    'Impact': impact,
                    'True_Severity': true_sev,
                    'Predicted_Severity': pred_sev,
                    'Severity_Confidence': round(float(confidence), 2),
                    'BERT_Category': bert_cat,
                    'BERT_Confidence': bert_conf
                })
                print(f"   * successfully processed and saved {cve_id}")
        except Exception as e:
            print(f"   [!] Error processing {cve_id} in background: {e}")
            
    # Re-train models with the newly added data
    ml_engine.train_all_models()

# ==============================================================================
# 4. API ENDPOINTS
# ==============================================================================

@app.get("/api/status")
def get_system_status():
    """Returns database sizes, model fitting specs, and general stats."""
    try:
        stats = db.get_stats()
        return {
            "status": "online",
            "cve_count": stats["total"],
            "avg_cvss": stats["avg_cvss"],
            "severities": stats["severities"],
            "exploits": stats["exploits"],
            "components": stats["components"],
            "models_trained": ml_engine.rf_model is not None,
            "rf_mae": round(ml_engine.rf_mae, 3),
            "rf_rmse": round(ml_engine.rf_rmse, 3),
            "memm_accuracy": round(ml_engine.memm_accuracy * 100, 1),
            "bert_loaded": ml_engine.bert_classifier is not None,
            "zero_shot_loaded": ml_engine.zero_shot_classifier is not None
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/cve/lookup")
def cve_lookup(cve_id: str = Query(..., description="The CVE ID to analyze (e.g. CVE-2021-44228)")):
    """Retrieves a single CVE. Searches database first, fallbacks to NVD API."""
    cve_id = cve_id.strip().upper()
    if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE ID format. Must be CVE-YYYY-NNNN(N)")

    # 1. Check local DB
    results, _ = db.fetch_all(limit=1, search=cve_id)
    if results:
        # Match exactly
        for row in results:
            if row['CVE_ID'] == cve_id:
                return {**row, "source": "local_database"}

    # 2. Query NVD API
    try:
        record = fetch_single_cve_nvd(cve_id)
        if not record:
            raise HTTPException(status_code=404, detail=f"Vulnerability {cve_id} not found in NVD database.")

        # Process record
        cleaned_desc = preprocess_text(record['Description'])
        exploit = extract_exploit_type(record['Description'])
        component = extract_component(record['Description'])
        impact = extract_impact(record['Description'])
        true_sev = cvss_to_severity(record['CVSS_Score'])
        
        # ML Engine predictions
        pred_cvss = ml_engine.predict_cvss_score(record['Description'])
        pred_sev = cvss_to_severity(pred_cvss)
        
        # Calculate matching confidence
        confidence = 1.0 - min(0.4, abs(record['CVSS_Score'] - pred_cvss) / 10.0)

        # Zero-shot severity prediction (BART-large-mnli)
        zs_severity, zs_confidence = 'UNKNOWN', 0.0
        try:
            zs_severity, zs_confidence = ml_engine.predict_severity_zero_shot(record['Description'])
        except Exception:
            pass

        # DistilBERT category prediction
        bert_cat, bert_conf = 'N/A', 0.0
        try:
            bert_cat, bert_conf = ml_engine.predict_category_bert(record['Description'])
        except Exception:
            pass

        processed_record = {
            'CVE_ID': record['CVE_ID'],
            'Description': record['Description'],
            'Cleaned_Description': cleaned_desc,
            'Year': record['Year'],
            'CVSS_Score': record['CVSS_Score'],
            'CWE': record['CWE'],
            'OS': record['OS'],
            'Exploit_Type': exploit,
            'Affected_Component': component,
            'Impact': impact,
            'True_Severity': true_sev,
            'Predicted_Severity': pred_sev,
            'Severity_Confidence': round(float(confidence), 2),
            'BERT_Category': bert_cat,
            'BERT_Confidence': bert_conf
        }

        # Save to DB
        db.save_cve(processed_record)
        
        # Retrain background models on new single entry addition
        ml_engine.train_all_models()

        return {
            **processed_record,
            "source": "nvd_api_live",
            "zero_shot_severity": zs_severity,
            "zero_shot_confidence": zs_confidence
        }

    except PermissionError as pe:
        raise HTTPException(status_code=429, detail=str(pe))
    except ConnectionError as ce:
        raise HTTPException(status_code=502, detail=str(ce))
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

@app.post("/api/cve/bulk-import")
def bulk_import(payload: BulkImportInput, background_tasks: BackgroundTasks):
    """Triggers background processing of a batch of CVEs to bypass rate limits gracefully."""
    if not payload.cve_ids:
        raise HTTPException(status_code=400, detail="cve_ids list cannot be empty")
    
    background_tasks.add_task(process_bulk_cves, payload.cve_ids)
    return {"message": f"Bulk import for {len(payload.cve_ids)} vulnerabilities started in background."}

@app.get("/api/cves")
def list_cves(
    limit: int = 25,
    offset: int = 0,
    search: str = "",
    severity: str = "ALL",
    exploit: str = "ALL"
):
    """Lists CVEs stored in the database with extensive filters, search, and pagination."""
    try:
        cves, total = db.fetch_all(limit=limit, offset=offset, search=search, severity=severity, exploit=exploit)
        return {
            "cves": cves,
            "total": total,
            "limit": limit,
            "offset": offset
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/models/train")
def train_models():
    """Triggers full machine learning model retraining."""
    success = ml_engine.train_all_models()
    if not success:
        raise HTTPException(status_code=500, detail="Model retraining failed. Ensure database has enough entries.")
    
    return {
        "message": "All models successfully retrained and saved!",
        "rf_mae": round(ml_engine.rf_mae, 3),
        "rf_rmse": round(ml_engine.rf_rmse, 3),
        "hmm_means": ml_engine.hmm_means,
        "memm_accuracy": round(ml_engine.memm_accuracy * 100, 1)
    }

@app.post("/api/models/train/rf")
def train_rf():
    """Retrain only the Random Forest Regressor + TF-IDF vectorizer."""
    success = ml_engine.train_random_forest()
    if not success:
        raise HTTPException(status_code=500, detail="Random Forest training failed.")
    return {
        "message": "Random Forest Regressor retrained and saved!",
        "rf_mae": round(ml_engine.rf_mae, 3),
        "rf_rmse": round(ml_engine.rf_rmse, 3)
    }

@app.post("/api/models/train/hmm")
def train_hmm():
    """Retrain only the Hidden Markov Model (Gaussian HMM)."""
    success = ml_engine.train_hmm()
    if not success:
        raise HTTPException(status_code=500, detail="HMM training failed.")
    return {
        "message": "Hidden Markov Model retrained and saved!",
        "hmm_means": ml_engine.hmm_means
    }

@app.post("/api/models/train/memm")
def train_memm():
    """Retrain only the Maximum Entropy Markov Model (MEMM)."""
    success = ml_engine.train_memm()
    if not success:
        raise HTTPException(status_code=500, detail="MEMM training failed.")
    return {
        "message": "MEMM retrained and saved!",
        "memm_accuracy": round(ml_engine.memm_accuracy * 100, 1)
    }

@app.get("/api/analysis/forecast")
def get_forecast():
    """Calculates yearly trend line forecasts using ARIMA and Linear Regression."""
    forecast = ml_engine.run_time_series_forecast()
    if forecast is None:
        raise HTTPException(status_code=400, detail="Not enough yearly history in database to build time series models (minimum 3 years).")
    return forecast

@app.get("/api/analysis/hmm")
def get_hmm_threat_states():
    """Analyzes CVSS threat state sequences and next-state transition matrices via Gaussian HMM."""
    hmm_data = ml_engine.run_hmm_analysis()
    if hmm_data is None:
        raise HTTPException(status_code=400, detail="HMM engine not trained or database empty.")
    return hmm_data

@app.post("/api/analysis/memm")
def get_memm_decoding(payload: MEMMForecastInput):
    """Calculates threat state transition probability given next simulated CVSS score."""
    memm_data = ml_engine.run_memm_analysis(next_observed_cvss=payload.next_cvss)
    if memm_data is None:
        raise HTTPException(status_code=400, detail="MEMM engine not trained or database empty.")
    return memm_data

@app.post("/api/database/reset")
def reset_database():
    """Resets the SQLite database and reloads default seed data."""
    try:
        db.clear_db()
        db.load_seed_data()
        ml_engine.train_all_models()
        return {"message": "Database reset and seed data reloaded successfully!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/bert/status")
def bert_status():
    """Returns the loading status of the BERT and Zero-Shot transformer models."""
    return {
        "bert_loaded": ml_engine.bert_classifier is not None,
        "zero_shot_loaded": ml_engine.zero_shot_classifier is not None,
        "bert_model": "distilbert-base-uncased",
        "zero_shot_model": "facebook/bart-large-mnli"
    }

@app.post("/api/bert/predict")
def bert_predict(payload: CVEInput):
    """Runs both DistilBERT category and Zero-Shot severity prediction on a single CVE description."""
    cve_id = payload.cve_id.strip().upper()
    # Try to find in DB
    results, _ = db.fetch_all(limit=1, search=cve_id)
    description = None
    for row in results:
        if row['CVE_ID'] == cve_id:
            description = row['Description']
            break
    if not description:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found in local database. Look it up first.")

    bert_cat, bert_conf = ml_engine.predict_category_bert(description)
    zs_sev, zs_conf = ml_engine.predict_severity_zero_shot(description)
    rf_cvss = ml_engine.predict_cvss_score(description)

    return {
        "cve_id": cve_id,
        "bert_category": bert_cat,
        "bert_confidence": bert_conf,
        "zero_shot_severity": zs_sev,
        "zero_shot_confidence": zs_conf,
        "rf_predicted_cvss": rf_cvss,
        "rf_predicted_severity": cvss_to_severity(rf_cvss)
    }

@app.post("/api/bert/finetune")
def finetune_bert(background_tasks: BackgroundTasks):
    """Triggers DistilBERT fine-tuning on the ag_news dataset (same as notebook Step 3.2)."""
    import gc
    ml_engine.bert_classifier = None
    gc.collect()
    background_tasks.add_task(run_bert_finetuning)
    return {"message": "DistilBERT fine-tuning started in background. This may take several minutes."}

def run_bert_finetuning():
    """Background task: fine-tunes DistilBERT on ag_news and saves to ./bert_cve_finetuned."""
    try:
        import os
        import gc
        ml_engine.bert_classifier = None
        gc.collect()
        os.environ['TOKENIZERS_PARALLELISM'] = 'false'
        from datasets import load_dataset
        from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer
        from sklearn.metrics import accuracy_score as sk_accuracy_score
        import numpy as np

        print("[BERT Fine-tune] Downloading ag_news dataset...")
        raw = load_dataset('ag_news')
        train_data = raw['train'].shuffle(seed=42).select(range(800))
        test_data = raw['test'].shuffle(seed=42).select(range(200))
        LABEL_NAMES = raw['train'].features['label'].names

        MODEL_NAME = 'distilbert-base-uncased'
        tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

        def tokenize(batch):
            return tokenizer(batch['text'], padding='max_length', truncation=True, max_length=128)

        train_tok = train_data.map(tokenize, batched=True, num_proc=1)
        test_tok = test_data.map(tokenize, batched=True, num_proc=1)
        cols = ['input_ids', 'attention_mask', 'label']
        train_tok.set_format(type='torch', columns=cols)
        test_tok.set_format(type='torch', columns=cols)

        model = AutoModelForSequenceClassification.from_pretrained(
            MODEL_NAME, num_labels=4,
            id2label={i: l for i, l in enumerate(LABEL_NAMES)},
            label2id={l: i for i, l in enumerate(LABEL_NAMES)}
        )

        def compute_metrics(eval_pred):
            logits, labels = eval_pred
            preds = np.argmax(logits, axis=-1)
            return {'accuracy': sk_accuracy_score(labels, preds)}

        import transformers
        tversion = tuple(int(x) for x in transformers.__version__.split('.')[:2])
        eval_kwarg = 'eval_strategy' if tversion >= (4, 41) else 'evaluation_strategy'

        # Generate new timestamped folder to avoid any file locks on Windows
        target_model_path = os.path.join(MODELS_DIR, f"bert_cve_finetuned_{int(time.time())}")

        training_args = TrainingArguments(
            output_dir=target_model_path,
            num_train_epochs=2,
            per_device_train_batch_size=16,
            per_device_eval_batch_size=32,
            **{eval_kwarg: 'epoch'},
            save_strategy='epoch',
            load_best_model_at_end=True,
            logging_steps=50,
            report_to='none',
        )

        trainer = Trainer(
            model=model, args=training_args,
            train_dataset=train_tok, eval_dataset=test_tok,
            compute_metrics=compute_metrics,
        )

        print("[BERT Fine-tune] Starting training (2 epochs on 800 samples)...")
        trainer.train()
        print("[BERT Fine-tune] Training complete! Saving model...")
        trainer.save_model(target_model_path)
        tokenizer.save_pretrained(target_model_path)

        # Release previous model memory mappings from the main thread
        ml_engine.bert_classifier = None
        gc.collect()

        # Clean up older timestamped directories (except the active one we just saved)
        import glob
        import shutil
        old_folders = glob.glob(os.path.join(MODELS_DIR, "bert_cve_finetuned_*"))
        
        # Also clean up legacy folder if present
        legacy_path = os.path.join(MODELS_DIR, "bert_cve_finetuned")
        if os.path.exists(legacy_path):
            old_folders.append(legacy_path)

        for folder in old_folders:
            if os.path.basename(folder) != os.path.basename(target_model_path):
                try:
                    shutil.rmtree(folder)
                except Exception:
                    pass  # It's locked by another process/thread, we will get it on next restart

        print(f"[BERT Fine-tune] Fine-tuned model saved successfully to {target_model_path}")
    except Exception as e:
        print(f"[BERT Fine-tune] ERROR: {e}")

# ==============================================================================
# 5. FRONTEND ROUTING & STATIC FILES
# ==============================================================================

@app.get("/")
def get_index():
    """Serves the main SIEM dashboard HTML page."""
    return FileResponse("static/index.html")

# Mount remaining static directories for CSS and JS files
app.mount("/", StaticFiles(directory="static"), name="static")

# ==============================================================================
# 6. EXECUTION RUNNER
# ==============================================================================

if __name__ == "__main__":
    print("[+] Starting local FastAPI server on http://localhost:8000...")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
