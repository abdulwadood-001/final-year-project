# HoneyBot-IoT — operator dashboard

React 19 + TypeScript single-page app (TanStack Router, TanStack Query, Tailwind CSS,
Recharts, offline d3-geo world map). It talks only to the HoneyBot-IoT API under
`/api` (REST) and `/api/ws` (WebSocket live push) on the same origin.

In production it is built inside `Dockerfile.dashboard` and served by Nginx with basic
auth — nothing to do by hand: `docker compose up -d --build`.

## Local development

```bash
cd dashboard
npm install
HONEYBOT_API=http://127.0.0.1:5000 npm run dev     # proxies /api and /api/ws to a running API
npm run build        # type-check + production build into dist/
npm test             # vitest
```

| Page | Data source |
|---|---|
| Overview | `/api/stats`, `/api/timeline`, `/api/attacks/recent`, `/api/map`, `/api/attackers/top` + live WebSocket |
| Attackers / attacker detail | `/api/attackers/top`, `/api/attackers/{ip}`, `/api/credentials/top`, `/api/commands/top`, `/api/campaigns` |
| Detections | `/api/detections`, `/api/mitre/summary`, `/api/iocs` |
| Devices / device detail | `/api/devices`, `/api/devices/{device}` (state, sensor history, change log) |
| Sessions / session replay | `/api/sessions/list`, `/api/sessions/{id}` |
| Malware | `/api/captures`, `/api/captures/{sha256}` |
| IOCs & MITRE | `/api/iocs`, `/api/mitre/summary`, `/api/export/stix` |
| Reports & Alerts | `/api/report`, `/api/report.pdf`, `/api/alerts`, `/api/ml/summary`, CSV/STIX/ML exports |
| Search | `/api/search?q=` |
