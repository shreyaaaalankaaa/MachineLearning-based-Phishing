# PhishGuard

PhishGuard is a Flask application for assessing phishing risk from the lexical and structural characteristics of a URL. It provides single-URL analysis, batch CSV processing, a JSON API, risk explanations, and an optional scikit-learn training pipeline.

The application does not visit submitted websites or perform DNS, WHOIS, certificate, or reputation lookups. This keeps analysis deterministic and avoids contacting potentially malicious hosts.

## Capabilities

- Extracts more than 30 URL features, including hostname entropy, domain structure, encoding, suspicious terms, IP-based hosts, shortened links, and path depth.
- Returns a classification, phishing probability, confidence value, and 0–100 risk score.
- Explains the strongest indicators contributing to a result.
- Supports CSV uploads and JSON batches of up to 500 URLs.
- Loads a persisted scikit-learn model when available.
- Uses a documented heuristic fallback when no trained model is present.
- Includes security headers, input-size limits, Docker support, tests, and GitHub Actions CI.

## Architecture

```text
Browser / API client
        |
        v
Flask routes and validation
        |
        v
URL normalization and feature extraction
        |
        +-----------------------------+
        |                             |
        v                             v
Persisted ML model             Heuristic fallback
        |                             |
        +-------------+---------------+
                      v
          Risk score and explanation
```

## Project structure

```text
.
├── app.py                     # Application factory and security headers
├── api_routes.py              # Web, batch, health, and prediction endpoints
├── feature_extractor.py       # Deterministic URL feature engineering
├── ml_pipeline.py             # Training, persistence, inference, and fallback logic
├── templates/                 # Server-rendered interface
├── static/                    # CSS and JavaScript
├── tests/                     # Route and feature tests
├── models/                    # Optional persisted model artifacts
├── .github/workflows/ci.yml   # Automated linting and tests
├── Dockerfile
├── docker-compose.yml
└── pyproject.toml
```

## Run locally

Python 3.11 or newer is required.

```bash
git clone https://github.com/shreyaaaalankaaa/MachineLearning-based-Phishing.git
cd MachineLearning-based-Phishing
python -m venv .venv
```

Activate the environment:

```bash
# macOS or Linux
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Install dependencies and start the server:

```bash
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`.

## Docker

```bash
docker compose up --build
```

The application will be available at `http://localhost:5000`.

## API

### Single prediction

```bash
curl -X POST http://localhost:5000/api/predict \
  -H "Content-Type: application/json" \
  -d '{"url":"http://198.51.100.42/verify-account/login"}'
```

### Batch prediction

```bash
curl -X POST http://localhost:5000/api/predict/batch \
  -H "Content-Type: application/json" \
  -d '{"urls":["https://github.com","http://198.51.100.42/login"]}'
```

### Health check

```bash
curl http://localhost:5000/api/health
```

Additional examples are available at `/docs` when the application is running.

## Training a model

The training pipeline accepts labeled URLs directly from Python:

```python
from ml_pipeline import pipeline

metadata = pipeline.train_model(
    urls=["https://example.com", "http://198.51.100.10/verify"],
    labels=[0, 1],
)
print(metadata)
```

A practical training dataset should contain substantially more samples, both classes, realistic class balance, and a documented source. The pipeline compares logistic regression and random forest models through stratified cross-validation, selects the strongest F1 result, evaluates it on a holdout split, and stores the final model under `models/`.

This repository intentionally does not claim a benchmark accuracy because no canonical dataset is bundled. Metrics depend on the dataset used for training and should be reported alongside its source, split strategy, and limitations.

## Testing

```bash
pip install pytest ruff
ruff check .
pytest -q
```

## Security and limitations

PhishGuard evaluates URL text only. It cannot verify page content, redirects, domain ownership, certificate history, hosting reputation, or newly registered domains. HTTPS is not treated as proof of legitimacy, and a low score does not guarantee safety.

Do not use this project as the sole basis for blocking access, reporting a domain, or making high-impact security decisions. A production system should combine lexical analysis with reputation feeds, DNS and registration signals, page-content analysis, sandboxing, monitoring, and human review.

## Author

**Shreya Lanka**  
Cybersecurity undergraduate interested in security engineering, machine learning, and software development.

- GitHub: `shreyaaaalankaaa`
- LinkedIn: `shreya-lanka-057a0b28a`
