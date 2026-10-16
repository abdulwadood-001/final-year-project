# Requirement Traceability Matrix (v0.7)

Functional requirements (FR) come from the scope modules. Each FR is linked to the automated
tests that verify it. Each automated test ID (AT) is one test function in `tests/`. Run them with
`pytest -v tests` (PostgreSQL and Redis running; DB-backed tests skip automatically without them).

| FR | Requirement (scope module) | Automated tests |
|---|---|---|
| FR-01 | Weak-credential profiles per device (M1-FE-1..3) | AT-22, AT-12, AT-13 |
| FR-02 | Device State Manager shared by all protocols (M1-FE-4) | AT-19, AT-29, AT-30 |
| FR-03 | MQTT 3.1.1 broker parsing (M2) | AT-05 – AT-10 |
| FR-04 | Interactive shells over SSH / Telnet (M2) | AT-14, AT-15, AT-17, AT-18, AT-31 |
| FR-05 | RTSP authentication, Basic + Digest (M2) | AT-10 – AT-13 |
| FR-06 | Command and URL capture, never fetched (M3) | AT-16, AT-24 |
| FR-07 | File capture, quarantine and YARA (M3) | AT-25 – AT-28, AT-35 |
| FR-08 | Lossless event store (M3) | AT-23, AT-34 |
| FR-09 | Detection with MITRE ATT&CK tags (M4) | AT-20, AT-21, AT-36 |
| FR-10 | IOC store and STIX 2.1 export (M4) | AT-37, AT-38 |
| FR-11 | Threat reports, PDF and CSV export (M4/M5) | AT-32, AT-42, AT-45 |
| FR-12 | Dashboard API, search and live push (M5) | AT-01 – AT-04, AT-40, AT-41, AT-43, AT-44 |
| FR-13 | ML dataset with weak labels (M8-FE-1 preparation) | AT-33, AT-39 |

## Automated test IDs

`(n)` = number of parametrised cases. 45 test functions = 78 executed test cases.

| AT | Test function |
|---|---|
| AT-01 | `tests/test_api.py::test_health` |
| AT-02 | `tests/test_api.py::test_stats_shape` |
| AT-03 | `tests/test_api.py::test_endpoints_return_json` (9) |
| AT-04 | `tests/test_api.py::test_search_requires_query` |
| AT-05 | `tests/test_parsers.py::test_remaining_length_roundtrip` (8) |
| AT-06 | `tests/test_parsers.py::test_remaining_length_handles_large_packet` |
| AT-07 | `tests/test_parsers.py::test_mqtt_connect_with_credentials` |
| AT-08 | `tests/test_parsers.py::test_mqtt_rejects_bad_protocol` |
| AT-09 | `tests/test_parsers.py::test_mqtt_subscribe_multiple_topics` |
| AT-10 | `tests/test_parsers.py::test_topic_matching` (7) |
| AT-11 | `tests/test_parsers.py::test_rtsp_parse_digest_header` |
| AT-12 | `tests/test_parsers.py::test_rtsp_digest_accepts_valid_default_credentials` |
| AT-13 | `tests/test_parsers.py::test_rtsp_digest_rejects_wrong_password` |
| AT-14 | `tests/test_parsers.py::test_shell_argument_tolerant_commands` |
| AT-15 | `tests/test_parsers.py::test_shell_mirai_preamble_is_silent` |
| AT-16 | `tests/test_parsers.py::test_shell_captures_url_without_fetching` |
| AT-17 | `tests/test_parsers.py::test_shell_command_chaining_and_pipes` |
| AT-18 | `tests/test_parsers.py::test_shell_exit` |
| AT-19 | `tests/test_parsers.py::test_shell_device_control_changes_state` |
| AT-20 | `tests/test_parsers.py::test_mitre_known_types_resolve` |
| AT-21 | `tests/test_parsers.py::test_mitre_command_tagging` |
| AT-22 | `tests/test_parsers.py::test_weak_credentials_per_device` |
| AT-23 | `tests/test_v07.py::test_sanitize_nul_everywhere` |
| AT-24 | `tests/test_v07.py::test_downloads_logged` (4) |
| AT-25 | `tests/test_v07.py::test_sniff_elf_architectures` |
| AT-26 | `tests/test_v07.py::test_shell_drop_is_captured_and_quarantined` |
| AT-27 | `tests/test_v07.py::test_trivial_writes_not_captured` |
| AT-28 | `tests/test_v07.py::test_yara_identifies_families` |
| AT-29 | `tests/test_v07.py::test_sensor_config_rejects_unknown_and_actor_key` |
| AT-30 | `tests/test_v07.py::test_sensor_history_recorded` |
| AT-31 | `tests/test_v07.py::test_telnet_iac_split_across_reads` |
| AT-32 | `tests/test_v07.py::test_pdf_renders_from_report_dict` |
| AT-33 | `tests/test_v07.py::test_weak_label_priority` |
| AT-34 | `tests/test_v07.py::test_nul_rows_are_stored` |
| AT-35 | `tests/test_v07.py::test_capture_indexed_and_yara_scanned` |
| AT-36 | `tests/test_v07.py::test_detections_include_malware_family` |
| AT-37 | `tests/test_v07.py::test_ioc_hits_are_idempotent` |
| AT-38 | `tests/test_v07.py::test_stix_bundle_is_valid_stix21` |
| AT-39 | `tests/test_v07.py::test_ml_dataset_labels` |
| AT-40 | `tests/test_v07.py::test_v07_endpoints` (10) |
| AT-41 | `tests/test_v07.py::test_attacker_and_session_detail` |
| AT-42 | `tests/test_v07.py::test_exports` |
| AT-43 | `tests/test_v07.py::test_devices_hide_api_token` |
| AT-44 | `tests/test_v07.py::test_websocket_relays_live_events` |
| AT-45 | `tests/test_v07.py::test_report_max_severity_is_ranked_not_alphabetical` |

The dashboard has 17 further unit tests (`cd dashboard && npm test`, vitest).
