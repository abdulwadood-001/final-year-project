# HoneyBot-IoT — ML Model Card (data ready at 70%, models at 100%)

> **Status at 70% (v0.7):** WBS 10.1 *data preparation & feature engineering* is done:
> `ml/features.py` builds the labelled per-session dataset live from the event store
> (`GET /api/ml/dataset.csv`, the Reports page, or `python -m ml.features out.csv`). Model
> training, evaluation and serving (WBS 10.2–10.6) are the 100% milestone; the metrics table
> below is filled in then.

## Intended use

Automatically label each captured attacker **session** by type, flag novel/zero-day behaviour,
and produce a plain-English threat narrative — removing manual log review for SOC analysts.

## Data

- **Source:** the `events` table of this honeypot (one row per interaction), aggregated to one
  feature vector per `session_id`.
- **Labels (weak):** the rule engine (`intel/rules.py`) already assigns an attack type to each
  session; these become the weak labels. The scope's "200,000+ labelled Cowrie sessions" is
  **not** a ready-made labelled set — we will state honestly that labels come from
  **rule-based weak labelling + self-generated simulated attacks + live-collected traffic.**
- **Simulated labelled traffic:** `tests/simulate_attacks.py` produces traffic for every class.

## Features (per session)

duration · auth attempts · distinct usernames/passwords · successful-login ratio · command
count · presence of `wget`/`curl`/`chmod`/`busybox`/`/tmp` · number of captured URLs · distinct
protocols · ports touched · inter-arrival-time stats · MQTT publishes to control topics · HTTP
404 count.

## Classes (6)

`brute-force · malware delivery · botnet C2 · port scan · protocol exploit · normal`
(the mapping from rule detections to these classes is in `docs/MILESTONE_60.md §5`.)

## Planned models

| Component | Algorithm | Output |
|---|---|---|
| Attack classifier | XGBoost | class + confidence |
| Anomaly detector | Isolation Forest | 0–1 novelty score |
| Threat narrator | local LLM (Ollama) or hosted API | 2–3 paragraph report |
| Risk score | weighted trend (LSTM only if enough data) | 0–100 per device / 24 h |

## Evaluation (to be completed)

| Metric | Target | Result |
|---|---|---|
| Accuracy | > 85% | _TBD_ |
| Macro F1 | — | _TBD_ |
| Per-class precision/recall | — | _TBD_ |
| Confusion matrix | — | _TBD_ |
| Inference latency | < 100 ms/session | _TBD_ |

5-fold stratified cross-validation; report the **real** number even if below 85%, and compare
against the rule-baseline to answer "isn't the model just learning your rules?".

## Limitations

Accuracy depends on data volume; early numbers may be low until enough live data is collected
(scope LI-6). The LLM narrator needs internet unless a local Ollama model is used (LI-7).
