"""
HoneyBot-IoT — Module 8 LLM Threat Narrator (scope M8-FE-3).

Turns a structured attack summary into a short, human-readable intelligence
narrative for SOC analysts and non-technical stakeholders.

Two backends:
  * "template" (default, offline): a deterministic, rule-based narrative builder.
    It needs no network — important for an isolated honeynet (LI-7) — and is what
    runs in the demo and the daily report.
  * "openai" / "ollama" (optional): if NARRATOR_BACKEND and the matching
    credentials/host are configured, the same structured summary is sent to an
    LLM (GPT-4o online, or a local LLaMA via Ollama for fully offline operation).
    Any failure falls back to the template backend, so a narrative is always produced.

The narrator never invents facts: online backends are given ONLY the structured
summary (no raw attacker payloads beyond what the summary carries), and the
template backend is pure string composition over the fields.
"""

import os
import json
import logging

log = logging.getLogger("narrator")

BACKEND = os.environ.get("NARRATOR_BACKEND", "template").strip().lower()

_CLASS_PHRASE = {
    "brute_force": "a credential brute-force / password-guessing attack",
    "malware_delivery": "malware delivery and post-exploitation",
    "botnet_c2": "botnet command-and-control / unauthorized device control",
    "port_scan": "reconnaissance and service scanning",
    "protocol_exploit": "exploitation of a public-facing service",
    "normal": "low-interest or benign scanning",
}
_SEV_WORD = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "moderate", "LOW": "low"}
_DEVICE_NAME = {"cctv": "CCTV camera", "smartlock": "smart lock", "sensor": "industrial sensor"}


def _rank_severity(sevs):
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    for s in order:
        if s in sevs:
            return s
    return "LOW"


def build_summary(session, prediction, detections):
    """Assemble the structured summary the narrator works from.
    session: dict (ip, device, protocol, duration_s, counts…); prediction: ml.model output;
    detections: list of dicts with attack_type/severity/details."""
    sevs = {d.get("severity") for d in detections}
    return {
        "ip": session.get("ip"),
        "device": session.get("device"),
        "protocol": session.get("protocol"),
        "ml_class": prediction.get("class"),
        "confidence": prediction.get("confidence"),
        "anomaly": prediction.get("anomaly"),
        "risk": prediction.get("risk"),
        "max_severity": _rank_severity(sevs),
        "detections": [d.get("attack_type") for d in detections],
        "detection_details": [d.get("details") for d in detections][:4],
        "auth_attempts": session.get("auth_attempts", 0),
        "commands": session.get("commands", 0),
        "downloads": session.get("download_attempts", 0),
        "state_changes": session.get("state_changes", 0),
    }


def _template_narrative(s):
    dev = _DEVICE_NAME.get(s["device"], s.get("device") or "device")
    cls = _CLASS_PHRASE.get(s["ml_class"], s.get("ml_class") or "suspicious activity")
    conf = int(round((s.get("confidence") or 0) * 100))
    risk = s.get("risk") or 0
    sev = _SEV_WORD.get(s["max_severity"], "low")

    p1 = (f"Source {s['ip']} engaged the emulated {dev} over {s.get('protocol') or 'the network'}. "
          f"The classifier labelled this session as {cls} "
          f"with {conf}% confidence and a risk score of {risk}/100"
          + (f", and the anomaly detector rated it unusual ({int(round((s.get('anomaly') or 0)*100))}/100), "
             "suggesting a technique outside the known-attack baseline"
             if (s.get("anomaly") or 0) >= 0.6 else "") + ".")

    acts = []
    if s.get("auth_attempts"):
        acts.append(f"{s['auth_attempts']} authentication attempt(s)")
    if s.get("commands"):
        acts.append(f"{s['commands']} shell command(s)")
    if s.get("downloads"):
        acts.append(f"{s['downloads']} payload download attempt(s)")
    if s.get("state_changes"):
        acts.append(f"{s['state_changes']} device-state change(s)")
    p2 = ("During the session the actor performed " + ", ".join(acts) + "."
          if acts else "The actor probed the service without completing authentication.")
    if s.get("detections"):
        uniq = ", ".join(dict.fromkeys(s["detections"]))
        p2 += f" The rule engine corroborated this with detections: {uniq}."

    recs = _recommendations(s)
    p3 = (f"Assessed severity is {sev}. Recommended actions: " + " ".join(recs))
    return "\n\n".join([p1, p2, p3])


def _recommendations(s):
    cls = s.get("ml_class")
    r = []
    if cls == "brute_force":
        r += ["enforce strong, unique device credentials and rate-limit authentication;",
              "block the source IP and monitor for credential reuse across devices."]
    elif cls == "malware_delivery":
        r += ["treat the captured sample as hostile and analyse it offline;",
              "block the download URL(s) as IOCs and hunt for the same hashes on the network."]
    elif cls == "botnet_c2":
        r += ["isolate the affected device class and review ICS/MQTT access controls;",
              "alert the OT team — unauthorized control commands were observed."]
    elif cls == "port_scan":
        r += ["add the source to a watch-list; scanning often precedes exploitation."]
    elif cls == "protocol_exploit":
        r += ["patch or virtual-patch the targeted endpoint and rotate any exposed secrets;",
              "review web/ICS logs for the same exploit path elsewhere."]
    else:
        r += ["no immediate action; retain for trend analysis."]
    if (s.get("risk") or 0) >= 70:
        r.append("Escalate to an analyst now given the high risk score.")
    return r


def _llm_narrative(summary):
    """Optional online/offline LLM backend. Returns None on any failure so the caller
    falls back to the template. Only the structured summary is sent."""
    prompt = ("You are a SOC threat analyst. Write a concise 3-paragraph intelligence "
              "narrative (plain English, no markdown) for this honeypot session. Cover what "
              "happened, the likely intent, a severity assessment and concrete defensive "
              "recommendations. Use only the facts given:\n" + json.dumps(summary, indent=2))
    try:
        if BACKEND == "ollama":
            import urllib.request
            host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
            body = json.dumps({"model": os.environ.get("OLLAMA_MODEL", "llama3.1"),
                               "prompt": prompt, "stream": False}).encode()
            req = urllib.request.Request(f"{host}/api/generate", data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read()).get("response", "").strip() or None
        if BACKEND == "openai":
            # Uses the official SDK if present and OPENAI_API_KEY is configured.
            from openai import OpenAI
            client = OpenAI()
            resp = client.chat.completions.create(
                model=os.environ.get("OPENAI_MODEL", "gpt-4o"),
                messages=[{"role": "user", "content": prompt}], temperature=0.3, max_tokens=400)
            return resp.choices[0].message.content.strip() or None
    except Exception as e:
        log.warning("LLM narrator backend '%s' failed, using template: %s", BACKEND, e)
    return None


def narrate(session, prediction, detections):
    """Public entry: return a narrative string for one session."""
    summary = build_summary(session, prediction, detections)
    if BACKEND in ("openai", "ollama"):
        text = _llm_narrative(summary)
        if text:
            return text
    return _template_narrative(summary)
