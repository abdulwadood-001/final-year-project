# HoneyBot-IoT — Module 8: AI Integration & Intelligent Threat Analysis

Module 8 adds the AI/ML intelligence layer over the honeypot's unified event store. It turns
raw attacker sessions into labelled, scored, human-readable intelligence with no manual log
review. Everything runs on the isolated honeynet; the only optional outbound path is a hosted
LLM, which is off by default.

## Pipeline

```
 events (PostgreSQL)
        │  ml/features.py  — one feature vector + weak label per session
        ▼
 ml/train.py  ──►  XGBoost classifier  +  Isolation Forest     (ml/artifacts/)
        │           (5-fold CV, metrics, feature importance)
        ▼
 ml/ml_api.py (ml_api container, FastAPI)  — serves classify / narrate / score_session
        ▲                                        │
        │ every 30 s                             ▼
 intel/engine.py ── ml/score.py ──►  ml_predictions table  ──►  /api/ml/* ──► dashboard
                     (classify finished sessions, store class + risk + narrative)
```

## Components (scope M8-FE-1 … FE-4)

| Scope item | Delivered | File |
|---|---|---|
| M8-FE-1 ML attack classifier | XGBoost, six classes, 5-fold stratified CV, confidence + full probabilities | `ml/train.py`, `ml/model.py` |
| M8-FE-2 Anomaly detector | Isolation Forest, 0–1 novelty score, flags out-of-baseline sessions | `ml/train.py`, `ml/model.py` |
| M8-FE-3 LLM threat narrator | 3-paragraph narrative + recommendations; offline template default, GPT-4o / Ollama optional | `ml/narrator.py` |
| M8-FE-4 Predictive risk scoring | transparent 0–100 risk per session, aggregated to per-device 24-h risk | `ml/model.py`, `/api/ml/risk` |
| ML serving microservice | FastAPI `ml_api` container; model autotrains a synthetic baseline on first boot | `ml/ml_api.py`, `Dockerfile.ml` |
| Classification storage (M4) | `ml_predictions` table, indexed by class / risk / device | `init.sql`, `ml/score.py` |

## The six classes

`brute_force · malware_delivery · botnet_c2 · port_scan · protocol_exploit · normal`

Weak labels come from the rule engine (`intel/rules.py`); the full mapping — including the
v0.8 attack types (false-data injection, token replay, container escape, …) — is in
`ml/features.py` `TYPE_TO_CLASS`.

## Features (29, per session)

Duration; auth attempts / successes / distinct usernames & passwords; command count;
download / exec / file-capture events; HTTP request & 404 counts; MQTT publishes / control /
wildcard subscriptions; RTSP requests & probes; malformed packets; state changes; command
keyword flags (`wget`/`curl`, `chmod`, busybox, `/tmp`, discovery); mean command length;
inter-event timing mean/std; and the source IP's protocol mix and session count within ±1 h.
The exact order is `ml/model.py` `FEATURES` and must match `ml/features.py`'s SQL.

## Risk score (M8-FE-4)

A transparent, explainable 0–100 score (not a black box): a benign session stays low; a
malicious class scales by its severity weight × classifier confidence, blended with the
anomaly score. `/api/ml/risk` aggregates it per device over 24 h and lists the top-risk
sessions for the dashboard. (A deep LSTM forecaster is documented as future work in the model
card — it needs far more longitudinal data than a lab run provides.)

## Running it

```bash
# in the full stack, the ml_api container trains a synthetic baseline on first boot:
docker compose up -d --build ml_api

# or locally:
python -m ml.train               # live data if available, else synthetic
python -m ml.ml_api              # serve on :5001
curl -s localhost:5001/model | jq .cv          # 5-fold CV metrics
```

A `POST /api/detect` pass then classifies finished sessions; the dashboard shows the AI class,
risk and narrative per session, and the per-device risk overview.

## Honesty & limitations

The cross-validation number on the synthetic baseline is high (~0.99) because the classes are
well-separated by their dominant engineered features; it validates the pipeline, **not**
real-world accuracy. The meaningful measurement is on live adversarial traffic (ongoing
collection, scope **LI-6**). Because the labels come from the rules, the model can partly learn
them — the timing/ratio features it relies on are signals the rules do not use. See
`docs/MODEL_CARD.md` for the full discussion.
