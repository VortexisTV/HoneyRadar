# HoneyRadar log store + query API

Server-side SQLite persistence so HoneyRadar can keep and search **all** events
over days/weeks. The live WebSocket is unchanged, this runs alongside it.

Two zero-dependency Python files (stdlib `sqlite3` + `http.server`; FTS5 ships
with CPython's SQLite):

- `honeyradar_store.py` — writes every normalized event into SQLite.
- `honeyradar_api.py` — read-only query API the HoneyRadar map calls.

---

## 1. Put the files on the VPS

```bash
sudo mkdir -p /opt/honeyradar
sudo nano /opt/honeyradar/honeyradar_store.py
```

Paste [honeyradar_store.py](https://raw.githubusercontent.com/VortexisTV/HoneyRadar/refs/heads/main/honeyradar_store.py) code and save.

```bash
sudo nano /opt/honeyradar/honeyradar_api.py
```

Paste [honeyradar_api.py](https://raw.githubusercontent.com/VortexisTV/HoneyRadar/refs/heads/main/honeyradar_api.py) code and save.

```bash
sudo chown -R cowrie:cowrie /opt/honeyradar
```

The DB is created automatically at `/opt/honeyradar/honeyradar.db` (WAL mode, so
the API can read while the bridge writes).

Restart the bridge and confirm rows are landing:

```bash
sudo systemctl restart cowrie-websocket
sqlite3 /opt/honeyradar/honeyradar.db "SELECT COUNT(*) FROM events; SELECT COUNT(*) FROM malware_samples;"
```

## 2. Run the query API as a service

```bash
sudo nano /etc/systemd/system/honeyradar-api.service
```

```ini
[Unit]
Description=HoneyRadar read-only query API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cowrie
Group=cowrie
Environment=HONEYRADAR_DB=/opt/honeyradar/honeyradar.db
Environment=HONEYRADAR_BIND=127.0.0.1
Environment=HONEYRADAR_PORT=8788
ExecStart=/usr/bin/python3 /opt/honeyradar/honeyradar_api.py
Restart=always
RestartSec=3
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now honeyradar-api
curl -s http://127.0.0.1:8788/api/health
```

## 3. Publish it privately over Tailscale

```bash
sudo tailscale serve --bg --https 8443 127.0.0.1:8788
sudo tailscale serve status
```

That gives you something like `https://vps-3ab2df8e.YOUR-TAILNET.ts.net:8443/`.
**That URL (with the `/api` path) is what you paste into the map's History panel.**
Do **not** open port 8788 in the VPS firewall — Tailscale is the only way in.

> If `:8443` collides with your existing WebSocket serve, pick another HTTPS port,
> or serve the API under a path prefix and adjust the History "API base URL".

## 4. Retention (keep the DB bounded)

A daily timer that prunes old rows and reclaims space:

```bash
sudo tee /opt/honeyradar/retention.sh >/dev/null <<'SH'
#!/usr/bin/env bash
DB=/opt/honeyradar/honeyradar.db
DAYS=30
CUT=$(( ($(date +%s) - DAYS*86400) * 1000 ))
sqlite3 "$DB" "DELETE FROM events WHERE ts < $CUT;
               DELETE FROM search_fts WHERE kind='event' AND CAST(ref AS INTEGER) NOT IN (SELECT id FROM events);
               PRAGMA wal_checkpoint(TRUNCATE);"
SH
sudo chmod +x /opt/honeyradar/retention.sh
```

Schedule it (cron example):

```bash
echo "17 4 * * * cowrie /opt/honeyradar/retention.sh" | sudo tee /etc/cron.d/honeyradar-retention
```

Port scans dominate volume; raise/lower `DAYS`, or add a rule that drops
`opencanary.portscan` faster than the rest if the file grows too quickly.

---

## API reference

All endpoints return JSON and send `Access-Control-Allow-Origin: *` (safe — it's
private behind Tailscale). Read-only; every query is parameterized.

| Endpoint | Params |
| --- | --- |
| `GET /api/search` | `q` (full-text), `from`, `to` (epoch ms or `YYYY-MM-DD`), `source`, `eventid`, `ip`, `malicious=1`, `limit` (≤500), `offset` |
| `GET /api/profile` | `ip` — aggregated dossier over all history |
| `GET /api/stats` | `from`, `to` — top IPs / ports / countries / creds + type counts |
| `GET /api/malware` | `q`, `sha256`, `malicious=1`, `limit`, `offset` |
| `GET /api/health` | row counts + endpoint list |

`q` is tokenized into AND'ed prefix terms over the FTS5 index
(`raw_json, src_ip, username, password, command, country, eventid, malware, sha256`).
For an exact IP match use `ip=`; for an exact hash use `sha256=`.

## Schema

`events(id, ts, received_at, source, eventid, src_ip, src_port, dst_ip, dst_port,
protocol, username, password, command, country, cc, city, asn, isp, sensor,
malicious, rep_score, actor, malware, raw_json)` — indexed on ts, src_ip, eventid,
malicious, country, dst_port, source.

`malware_samples(sha256 PK, md5, sha1, first_seen, last_seen, hits, filename, size,
score, malicious, malware, clamav_infected, clamav_sig, yara, vt_malicious, vt_total,
vt_type, vt_popular, mb_found, mb_tags, raw_json)` — deduped by SHA-256 (re-scans
bump `hits` + `last_seen`).
