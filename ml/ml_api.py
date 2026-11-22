"""
HoneyBot-IoT — Module 8 inference microservice (scope M8: FastAPI ml_api).

A small, internal FastAPI service that serves the trained models so the rest of
the stack (intel engine, dashboard API) can request a classification, an anomaly
score, a risk score and an LLM/template threat narrative for a session WITHOUT
loading XGBoost itself. It runs in its own container on the internal backnet.

    GET  /health                → liveness + whether a model is loaded
    GET  /model                 → model metadata (classes, CV metrics, features)
    POST /classify              → {features:{…}} → class/confidence/probabilities/anomaly/risk
    POST /narrate               → {session:{…}, prediction:{…}, detections:[…]} → narrative
    POST /score_session         → {session:{…}} → classify + narrate in one call

No endpoint runs attacker input or opens an outbound connection (the optional
LLM narrator backend is the only exception, and only when explicitly configured).
"""

import os
import sys
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ml.model import Predictor, CLASSES
from ml import narrator

logging.basicConfig(level=logging.INFO, format="%(asctime)s | ml_api | %(message)s")
log = logging.getLogger("ml_api")

PORT = int(os.environ.get("ML_API_PORT", 5001))
app = FastAPI(title="HoneyBot-IoT ML API", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/health")
async def health():
    p = Predictor.get()
    return {"status": "ok", "model_loaded": p.available(), "classes": CLASSES}


@app.get("/model")
async def model():
    p = Predictor.get()
    if not p.available():
        return JSONResponse({"error": "no model trained", "hint": "run python -m ml.train"},
                            status_code=503)
    return p.meta


@app.post("/classify")
async def classify(request: Request):
    body = await request.json()
    feats = body.get("features", body)
    return Predictor.get().predict(feats)


@app.post("/narrate")
async def narrate(request: Request):
    body = await request.json()
    text = narrator.narrate(body.get("session", {}), body.get("prediction", {}),
                            body.get("detections", []))
    return {"narrative": text, "backend": narrator.BACKEND}


@app.post("/score_session")
async def score_session(request: Request):
    body = await request.json()
    session = body.get("session", body)
    detections = body.get("detections", [])
    pred = Predictor.get().predict(session)
    text = narrator.narrate(session, pred, detections)
    return {"prediction": pred, "narrative": text}


def _train_if_missing():
    """Self-contained demo: if no model has been trained yet, train one on synthetic
    data so the service is useful on first boot (live data refines it via `python -m
    ml.train`). Controlled by ML_AUTOTRAIN (default on)."""
    if Predictor.get().available() or os.environ.get("ML_AUTOTRAIN", "1") != "1":
        return
    log.info("no trained model found — training a synthetic baseline (ML_AUTOTRAIN=1)")
    try:
        import subprocess
        subprocess.run([sys.executable, "-m", "ml.train", "--synthetic",
                        os.environ.get("ML_AUTOTRAIN_PER_CLASS", "400")], check=True)
        Predictor._instance = None          # force reload
    except Exception as e:
        log.error("auto-train failed: %s", e)


def main():
    _train_if_missing()
    log.info("HoneyBot-IoT ML API on :%d (model loaded: %s)", PORT, Predictor.get().available())
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
