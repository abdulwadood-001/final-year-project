"""
HoneyBot-IoT — synthetic labelled session generator for Module 8.

A honeypot that has only just been deployed has too few live sessions to train on
(limitation LI-6). This module generates realistic, per-class feature vectors with
the SAME schema as ml.features, so the classifier and Isolation Forest can be
trained and demonstrated immediately; the live data then augments / replaces it.

Each class is drawn from a plausible distribution over the real features (e.g. a
brute-force session has many auth attempts and distinct passwords but few
commands). The distributions are intentionally separable but noisy, so the model
has to learn and 5-fold CV is meaningful, while never being perfectly clean.
"""

import random

from ml.model import FEATURES


def _n(rng, mu, sd, lo=0.0, hi=None):
    v = rng.gauss(mu, sd)
    v = max(lo, v)
    return min(v, hi) if hi is not None else v


def _base(rng):
    return {f: 0.0 for f in FEATURES}


def _sample(label, rng):
    f = _base(rng)
    f["ip_sessions_1h"] = _n(rng, 2, 2, 1)
    f["ip_protocols_1h"] = _n(rng, 1, 1, 1, 5)
    if label == "brute_force":
        n = _n(rng, 25, 20, 3)
        f.update(auth_attempts=n, distinct_passwords=_n(rng, n * 0.8, 4, 1),
                 distinct_usernames=_n(rng, 3, 3, 1), auth_success=rng.choice([0, 0, 0, 1]),
                 events_total=n + _n(rng, 2, 2), duration_s=_n(rng, 40, 60, 1),
                 mean_gap_s=_n(rng, 0.8, 1.5), std_gap_s=_n(rng, 0.5, 1))
    elif label == "malware_delivery":
        cmds = _n(rng, 8, 5, 2)
        f.update(auth_attempts=_n(rng, 2, 1, 1), auth_success=1, commands=cmds,
                 download_attempts=_n(rng, 2, 1.5, 1), exec_attempts=_n(rng, 1, 1),
                 file_events=_n(rng, 1, 1), cmd_download=_n(rng, 2, 1, 1),
                 cmd_chmod=_n(rng, 1, 1), cmd_busybox=_n(rng, 2, 2),
                 cmd_tmp_paths=_n(rng, 2, 1), cmd_discovery=_n(rng, 3, 2),
                 mean_cmd_len=_n(rng, 35, 15, 5), events_total=cmds + _n(rng, 6, 3),
                 duration_s=_n(rng, 60, 50, 3))
    elif label == "botnet_c2":
        if rng.random() < 0.5:                 # MQTT C2 flavour
            pub = _n(rng, 30, 25, 5)
            f.update(mqtt_publishes=pub, mqtt_control=_n(rng, pub * 0.4, 3),
                     mqtt_wildcard_subs=_n(rng, 1, 1), events_total=pub + _n(rng, 3, 2),
                     duration_s=_n(rng, 120, 90, 5))
        else:                                  # ICS command/manipulation flavour
            sc = _n(rng, 6, 4, 2)
            f.update(state_changes=sc, commands=_n(rng, 3, 2), auth_success=1,
                     events_total=sc + _n(rng, 5, 3), duration_s=_n(rng, 50, 40, 3))
    elif label == "port_scan":
        f.update(events_total=_n(rng, 2, 1, 1), http_404=_n(rng, 6, 6),
                 http_requests=_n(rng, 8, 7), malformed=_n(rng, 1, 2),
                 rtsp_route_probes=_n(rng, 2, 3), duration_s=_n(rng, 3, 5, 0),
                 ip_protocols_1h=_n(rng, 3, 1.5, 1, 5), ip_sessions_1h=_n(rng, 8, 6, 2))
    elif label == "protocol_exploit":
        f.update(http_requests=_n(rng, 5, 4, 1), malformed=_n(rng, 2, 2),
                 state_changes=_n(rng, 1, 1), events_total=_n(rng, 6, 4, 1),
                 mean_cmd_len=_n(rng, 60, 30, 5), duration_s=_n(rng, 20, 20, 1))
    else:  # normal / benign scan
        f.update(events_total=_n(rng, 2, 1, 1), auth_attempts=_n(rng, 0.4, 0.8),
                 http_requests=_n(rng, 1, 1), duration_s=_n(rng, 5, 8, 0),
                 mean_gap_s=_n(rng, 3, 4))
    # cross-class noise so classes overlap and 5-fold CV is a real test (not a
    # perfectly separable toy): jitter many features, and sometimes borrow a
    # characteristic feature from another class (realistic ambiguity).
    for k in FEATURES:
        if rng.random() < 0.18:
            f[k] = max(0.0, f[k] + _n(rng, 1.5, 3))
    if rng.random() < 0.18:                       # blend in a confusing signal
        other = _sample_raw(rng.choice([c for c in _OTHER if c != label]), rng)
        for k in rng.sample(FEATURES, 4):
            f[k] = round((f[k] + other.get(k, 0)) / 2, 3)
    return f


# names kept separate to avoid recursion through the public _sample
_OTHER = ["brute_force", "malware_delivery", "botnet_c2", "port_scan", "protocol_exploit", "normal"]


def _sample_raw(label, rng):
    """A clean per-class draw (no cross-class blending) used only to borrow features."""
    f = _base(rng)
    if label == "brute_force":
        n = _n(rng, 25, 20, 3)
        f.update(auth_attempts=n, distinct_passwords=_n(rng, n * 0.8, 4, 1))
    elif label == "malware_delivery":
        f.update(commands=_n(rng, 8, 5, 2), download_attempts=_n(rng, 2, 1.5, 1),
                 cmd_busybox=_n(rng, 2, 2))
    elif label == "botnet_c2":
        f.update(mqtt_publishes=_n(rng, 30, 25, 5), state_changes=_n(rng, 6, 4))
    elif label == "port_scan":
        f.update(http_404=_n(rng, 6, 6), ip_sessions_1h=_n(rng, 8, 6, 2))
    elif label == "protocol_exploit":
        f.update(http_requests=_n(rng, 5, 4, 1), malformed=_n(rng, 2, 2))
    else:
        f.update(events_total=_n(rng, 2, 1, 1))
    return f


def generate(per_class=400, seed=42):
    """Return (rows, labels): `per_class` synthetic sessions for each of the six classes."""
    rng = random.Random(seed)
    from ml.model import CLASSES
    rows, labels = [], []
    for label in CLASSES:
        for _ in range(per_class):
            rows.append(_sample(label, rng))
            labels.append(label)
    idx = list(range(len(rows)))
    rng.shuffle(idx)
    return [rows[i] for i in idx], [labels[i] for i in idx]
