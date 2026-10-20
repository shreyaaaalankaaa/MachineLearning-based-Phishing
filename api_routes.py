from __future__ import annotations

import csv
import io

from flask import Blueprint, jsonify, render_template, request

from ml_pipeline import pipeline

bp = Blueprint("main", __name__)


def _error(message: str, status: int = 400):
    return jsonify({"success": False, "error": message}), status


@bp.get("/")
def index():
    return render_template("index.html", model_info=pipeline.get_model_info())


@bp.post("/predict")
def predict_page():
    try:
        result = pipeline.predict(request.form.get("url", ""))
        return render_template("results.html", result=result)
    except ValueError as exc:
        return render_template("index.html", model_info=pipeline.get_model_info(), error=str(exc)), 400


@bp.get("/docs")
def docs():
    return render_template("api_docs.html")


@bp.get("/api/health")
def health():
    return jsonify({"success": True, "status": "ok", "model": pipeline.get_model_info()})


@bp.get("/api/model/info")
def model_info():
    return jsonify({"success": True, "data": pipeline.get_model_info()})


@bp.post("/api/predict")
def api_predict():
    payload = request.get_json(silent=True) or {}
    try:
        return jsonify({"success": True, "data": pipeline.predict(str(payload.get("url", "")))})
    except ValueError as exc:
        return _error(str(exc))


@bp.post("/api/predict/batch")
def api_batch():
    payload = request.get_json(silent=True) or {}
    urls = payload.get("urls")
    if not isinstance(urls, list) or not urls:
        return _error("'urls' must be a non-empty list")
    if len(urls) > 500:
        return _error("Batch requests are limited to 500 URLs")
    results: list[dict] = [{} for _ in urls]
    valid: list[tuple[int, str]] = []
    for index, url in enumerate(urls):
        try:
            pipeline.extractor.normalize(str(url))
            valid.append((index, str(url)))
        except ValueError as exc:
            results[index] = {"index": index, "url": str(url), "error": str(exc)}
    scored = pipeline.predict_batch([url for _, url in valid])
    for (index, _), prediction in zip(valid, scored):
        results[index] = {"index": index, **prediction}
    return jsonify({"success": True, "data": {"count": len(results), "predictions": results}})


@bp.post("/batch")
def batch_upload():
    upload = request.files.get("file")
    if not upload or not upload.filename.lower().endswith(".csv"):
        return render_template("index.html", model_info=pipeline.get_model_info(), error="Upload a CSV file with a 'url' column."), 400
    text = upload.stream.read().decode("utf-8-sig", errors="replace")
    rows = list(csv.DictReader(io.StringIO(text)))
    if not rows or "url" not in (rows[0].keys() if rows else []):
        return render_template("index.html", model_info=pipeline.get_model_info(), error="The CSV must contain a 'url' column."), 400
    if len(rows) > 500:
        return render_template("index.html", model_info=pipeline.get_model_info(), error="CSV uploads are limited to 500 rows."), 400
    results: list[dict] = [{} for _ in rows]
    valid: list[tuple[int, str]] = []
    for index, row in enumerate(rows):
        url = row.get("url", "")
        try:
            pipeline.extractor.normalize(url)
            valid.append((index, url))
        except ValueError as exc:
            results[index] = {"url": url, "prediction": "invalid", "risk_score": 0, "error": str(exc)}
    for (index, _), prediction in zip(valid, pipeline.predict_batch([url for _, url in valid])):
        results[index] = prediction
    return render_template("batch_results.html", results=results)
