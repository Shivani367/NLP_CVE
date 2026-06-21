---

title: CVE Threat Intelligence Dashboard
emoji: 🛡️
colorFrom: blue
colorTo: red
sdk: streamlit
app_file: app.py
pinned: false
license: mit
short_description: AI-powered CVE vulnerability analysis using DistilBERT, BART, spaCy NER, and CVSS severity prediction.
tags:

* cybersecurity
* nlp
* machine-learning
* transformers
* distilbert
* bart
* threat-intelligence
* vulnerability-analysis

---



# CVE Threat Intelligence Dashboard 🛡️

A modern, high-performance, and offline-capable SIEM Threat Intelligence Dashboard that analyzes, predicts, and logs Common Vulnerabilities and Exposures (CVE) severity and categories. The application utilizes a combination of classical machine learning and advanced NLP transformer models to automate vulnerability classification.

---

## 🚀 Key Features

* **Multi-Model Intelligence**:
  - **Random Forest**: Predicts CVSS scores and threat severity.
  - **Gaussian HMM (Hidden Markov Model)**: Sequential vulnerability clustering.
  - **MEMM (Maximum Entropy Markov Model)**: Structural threat tag extraction.
  - **DistilBERT (Transformer)**: Fine-tuned text classification for vulnerability categorizations.
  - **Zero-Shot BART (Transformer)**: Classifies real-time severity levels from textual descriptions without specific training.
* **Modern Web Interface**: Glassmorphic dashboard UI with micro-animations, real-time metrics, interactive prediction console, and system logs.
* **On-Demand Retraining Panel**: Trigger full retraining or individual model updates (RF, HMM, MEMM, or DistilBERT fine-tuning) asynchronously in the background.
* **Self-Contained Model Cache**: Eagerly loads local models from disk (`trained_models/`) for quick startups, performing offline inference without internet requests.
* **Git LFS Configured**: Essential large model weights are fully version-controlled using Git Large File Storage.

---

## 🛠️ Tech Stack

* **Backend**: FastAPI, PyTorch, Hugging Face Transformers, Scikit-learn, joblib, SQLite.
* **Frontend**: Vanilla HTML5, CSS3, JavaScript.

---

## 🏃 Getting Started

### Prerequisites
Make sure Python 3.10+ and Git are installed on your system.

### Installation & Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/destroyer929/NLP_CVE.git
   cd NLP_CVE
   ```

2. **Create the Virtual Environment**:
   * **PowerShell**:
     ```powershell
     python -m venv cve
     .\cve\Scripts\Activate.ps1
     ```
   * **Command Prompt (CMD)**:
     ```cmd
     python -m venv cve
     call cve\Scripts\activate.bat
     ```

3. **Install Dependencies**:
   ```bash
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Launch the Application**:
   ```bash
   python main.py
   ```
   *(Alternatively, run the automated launcher script: `.\run.bat`)*

5. **Access Dashboard**:
   Open **[http://localhost:8000](http://localhost:8000)** in your web browser.

---

## 📂 Project Structure

```text
├── main.py                 # FastAPI backend server & background tasks
├── cve_pipeline.py         # DB Operations & ML Engine definition
├── requirements.txt        # Package dependencies list
├── run.bat                 # Automated startup script
├── static/                 # HTML, CSS, and JS frontend assets
├── trained_models/         # Serialized model weights (Joblib & Safetensors)
└── README.md               # Project documentation
```
