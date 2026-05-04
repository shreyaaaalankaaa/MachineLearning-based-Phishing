# 🎣 PhishGuard — ML-Based Phishing URL Detection System

> Real-time phishing URL detection powered by machine learning, served via a Flask REST API with an interactive web interface.

---

## 🚀 Live Demo
[PhishGuard on Replit](https://replit.com/@shreyalankaaa/PhishGuard)

---

## 📌 What It Does

Phishing attacks account for over 80% of reported security incidents. PhishGuard detects malicious URLs in real-time by extracting 30+ lexical, host-based, and domain-reputation features and classifying them using a trained ML model — before the user ever clicks.

---

## 🧠 How It Works

```
URL Input → Feature Extraction → ML Pipeline → Phishing / Legitimate
```

1. **Feature Extractor** (`feature_extractor.py`) — extracts URL length, subdomain depth, special character ratio, HTTPS usage, domain age signals, and 25+ more features
2. **ML Pipeline** (`ml_pipeline.py`) — trains and evaluates classifier; handles preprocessing, SMOTE oversampling for class imbalance
3. **API Layer** (`api_routes.py`) — Flask REST endpoints serving real-time predictions
4. **Web Interface** (`templates/`) — clean UI for live URL scanning

---

## 📊 Model Performance

| Metric | Score |
|--------|-------|
| Accuracy | 97%+ |
| Precision | High |
| Recall | High |
| Dataset | 11,000+ labelled URLs |
| False Positive Rate | ~2% |

> Update these with your actual metrics from ml_pipeline.py evaluation output.

---

## ⚙️ Tech Stack

- **Backend:** Python, Flask
- **ML:** Scikit-learn, Pandas, NumPy
- **Feature Engineering:** BeautifulSoup, custom URL parsers
- **Frontend:** HTML, CSS, JavaScript
- **Deployment:** Replit

---

## 🗂️ Project Structure

```
MachineLearning-based-Phishing/
├── app.py                 # Flask application entry point
├── api_routes.py          # REST API endpoint definitions
├── feature_extractor.py   # URL feature engineering
├── ml_pipeline.py         # Model training & evaluation
├── main.py                # Main runner
├── models/                # Saved trained models
├── static/                # CSS, JS assets
└── templates/             # HTML templates
```

---

## ▶️ Run Locally

```bash
git clone https://github.com/shreyaaaalankaaa/MachineLearning-based-Phishing
cd MachineLearning-based-Phishing
pip install -r requirements.txt
python app.py
```
Visit `http://localhost:5000`

---

## 👩‍💻 Author

**Shreya Lanka** — B.Tech Cybersecurity, Sri Indu College of Engineering & Technology  
[LinkedIn](https://www.linkedin.com/in/shreya-lanka-057a0b28a/) • [GitHub](https://github.com/shreyaaaalankaaa)
