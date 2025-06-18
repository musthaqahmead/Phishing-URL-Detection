# 🛡️ Phishing URL Detection System using Machine Learning

A complete web-based solution that uses **Machine Learning** and **External Threat Intelligence APIs** to identify and classify phishing URLs. This system integrates URL feature extraction, model training, and a user-friendly Flask-based web interface to enhance internet safety.

![Web Interface - Example](https://github.com/user-attachments/assets/17ee7922-8cee-4543-a470-02459c21d1de)


---

## 📌 Table of Contents
- [Introduction](#introduction)
- [Project Features](#project-features)
- [Tech Stack](#tech-stack)
- [Directory Structure](#directory-structure)
- [Installation](#installation)
- [Running the Project](#running-the-project)
- [Model Training](#model-training)
- [Feature Overview](#feature-overview)
- [Screenshots](#screenshots)
- [Conclusion & Future Scope](#conclusion--future-scope)
- [Contributors](#contributors)

---

## 🧠 Introduction

**Phishing URL Detection System** uses a Random Forest ML model trained on 41 carefully engineered features to detect malicious URLs. It includes both **static analysis** (URL, domain, certificate) and **real-time security checks** via:
- Google Safe Browsing API
- VirusTotal API

The system presents a clear prediction, a **safety score**, and a breakdown of features that contributed to the result.

---

## 🚀 Project Features

✅ Feature extraction from lexical, content-based, domain-based, SSL, and external sources  
✅ RandomForestClassifier with hyperparameter tuning (GridSearchCV)  
✅ Flask web application for interactive URL input  
✅ API integration with Google Safe Browsing & VirusTotal  
✅ Displays analysis results, score, positive/negative indicators, and recommendations  
✅ Local blacklist file support for fast lookups  

---

## 🛠️ Tech Stack

**Frontend:** HTML, CSS (via Flask templates)  
**Backend:** Python (Flask)  
**ML Framework:** Scikit-learn  
**Other Libraries:** pandas, numpy, requests, beautifulsoup4, whois, ipaddress, pyOpenSSL, certifi  
**APIs Used:** Google Safe Browsing v4, VirusTotal API v3  

---

## 📁 Directory Structure
Phishing-URL-Detection/
|
|-- dataset/
|   `-- phishing_dataset.csv
|
|-- local_blacklist/
|   `-- blacklist_urls.txt
|
|-- pickle/
|   |-- Phishing_model.pkl
|   `-- feature_names.json
|
|-- static/
|   `-- style.css
|
|-- templates/
|   `-- index.html
|
|-- app.py
|-- feature.py
|-- train_model.py
|-- requirements.txt
`-- README.md



---

## 🧪 Installation

1. **Clone the repository**
```bash
git clone https://github.com/musthaqahmead/Phishing-URL-Detection.git
cd Phishing-URL-Detection
# 1. Clone the repository
git clone https://github.com/musthaqahmead/Phishing-URL-Detection.git
cd Phishing-URL-Detection

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set your API keys (Optional: create a .env file or set in app.py)
# Open app.py and update these lines:
# Example (edit inside app.py):
# GSB_API_KEY = "your_google_safe_browsing_key"
# VT_API_KEY = "your_virustotal_api_key"

# 5. Run the Flask web application
python app.py
# Visit the app in your browser:
# http://127.0.0.1:5000/

# 6. (Optional) Retrain the model if needed
python train_model.py
# This will generate:
#   - pickle/Phishing_model.pkl
#   - pickle/feature_names.json
