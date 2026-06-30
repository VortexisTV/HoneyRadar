"""
honeyradar_api.py - read-only query API over the HoneyRadar SQLite DB.

    HONEYRADAR_DB=/opt/honeyradar/honeyradar.db \
    HONEYRADAR_BIND=127.0.0.1 HONEYRADAR_PORT=8788 \
    python3 honeyradar_api.py

Then publish it privately:  sudo tailscale serve --bg 8788

Endpoints (all return JSON, CORS-open since it lives behind Tailscale):
  GET /api/search?q=&from=&to=&source=&eventid=&ip=&malicious=&limit=&offset=
  GET /api/profile?ip=
  GET /api/stats?from=&to=
  GET /api/malware?q=&sha256=&malicious=&limit=&offset=
  GET /api/health

Read-only: opens SQLite with mode=ro, every query is parameterised. Stdlib only.
"""

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DB_PATH = os.getenv("HONEYRADAR_DB", "/opt/honeyradar/honeyradar.db")
BIND = os.getenv("HONEYRADAR_BIND", "127.0.0.1")
PORT = int(os.getenv("HONEYRADAR_PORT", "8788"))
MAX_LIMIT = 500


def _connect():
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _ts(value):
    """Accept epoch ms, epoch s, or an ISO date/datetime -> epoch ms."""
    if value in (None, ""):
        return None
    try:
        n = int(value)
        return n if n > 10_000_000_000 else n * 1000  # treat <=10^10 as seconds
    except (TypeError, ValueError):
        pass
    s = str(value).strip().replace("T", " ").replace("Z", "")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return int(datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp() * 1000)
        except ValueError:
            continue
    return None


def _int(v, default=None):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _fts_query(q):
    """User text -> safe FTS5 MATCH expression (AND of prefix tokens)."""
    toks = [t for t in re.findall(r"[A-Za-z0-9_]+", q or "") if t][:12]
    return " ".join(t + "*" for t in toks) if toks else None


def _event_filters(p, alias=""):
    clauses, vals = [], []
    frm, to = _ts(p.get("from")), _ts(p.get("to"))
    if frm is not None:
        clauses.append(f"{alias}ts >= ?"); vals.append(frm)
    if to is not None:
        clauses.append(f"{alias}ts <= ?"); vals.append(to)
    if p.get("source"):
        clauses.append(f"{alias}source = ?"); vals.append(p["source"])
    if p.get("eventid"):
        clauses.append(f"{alias}eventid = ?"); vals.append(p["eventid"])
    if p.get("ip"):
        clauses.append(f"({alias}src_ip = ? OR {alias}dst_ip = ?)"); vals += [p["ip"], p["ip"]]
    if p.get("malicious") in ("1", "true", "yes", "on"):
        clauses.append(f"{alias}malicious = 1")
    return clauses, vals


# ---------------------------------------------------------------- queries
def search_events(conn, p):
    limit = min(_int(p.get("limit"), 100) or 100, MAX_LIMIT)
    offset = max(_int(p.get("offset"), 0) or 0, 0)
    fts = _fts_query(p.get("q"))
    if fts:
        clauses, vals = _event_filters(p, "e.")
        where = "search_fts.kind='event' AND search_fts MATCH ?" + ("".join(" AND " + c for c in clauses))
        base = "FROM search_fts JOIN events e ON e.id = CAST(search_fts.ref AS INTEGER) WHERE " + where
        total = conn.execute("SELECT COUNT(*) " + base, [fts] + vals).fetchone()[0]
        rows = conn.execute(
            "SELECT e.* " + base + " ORDER BY e.ts DESC LIMIT ? OFFSET ?",
            [fts] + vals + [limit, offset]).fetchall()
    else:
        clauses, vals = _event_filters(p, "")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        total = conn.execute("SELECT COUNT(*) FROM events" + where, vals).fetchone()[0]
        rows = conn.execute(
            "SELECT * FROM events" + where + " ORDER BY ts DESC LIMIT ? OFFSET ?",
            vals + [limit, offset]).fetchall()
    return {"total": total, "limit": limit, "offset": offset,
            "rows": [dict(r) for r in rows]}


def profile(conn, ip):
    if not ip:
        return {"error": "ip required"}
    agg = conn.execute(
        "SELECT COUNT(*) n, MIN(ts) first, MAX(ts) last, "
        "MAX(malicious) malicious, MAX(rep_score) rep_score "
        "FROM events WHERE src_ip = ?", (ip,)).fetchone()
    if not agg or agg["n"] == 0:
        return {"ip": ip, "found": False, "count": 0}
    last = conn.execute(
        "SELECT country, cc, city, asn, isp, actor, malware, rep_score, malicious "
        "FROM events WHERE src_ip = ? ORDER BY ts DESC LIMIT 1", (ip,)).fetchone()

    def top(sql):
        return [dict(r) for r in conn.execute(sql, (ip,)).fetchall()]

    return {
        "ip": ip, "found": True, "count": agg["n"],
        "first_seen": agg["first"], "last_seen": agg["last"],
        "malicious": bool(agg["malicious"]), "rep_score": agg["rep_score"],
        "geo": {k: (last[k] if last else None) for k in
                ("country", "cc", "city", "asn", "isp", "actor", "malware")},
        "types": top("SELECT eventid k, COUNT(*) c FROM events WHERE src_ip=? "
                     "GROUP BY eventid ORDER BY c DESC"),
        "top_creds": top("SELECT (COALESCE(username,'')||' / '||COALESCE(password,'')) k, COUNT(*) c "
                         "FROM events WHERE src_ip=? AND username IS NOT NULL GROUP BY k ORDER BY c DESC LIMIT 10"),
        "top_commands": top("SELECT command k, COUNT(*) c FROM events WHERE src_ip=? AND command IS NOT NULL "
                            "GROUP BY command ORDER BY c DESC LIMIT 10"),
        "top_ports": top("SELECT dst_port k, COUNT(*) c FROM events WHERE src_ip=? AND dst_port IS NOT NULL "
                         "GROUP BY dst_port ORDER BY c DESC LIMIT 15"),
        "recent": top("SELECT ts, eventid, dst_port, protocol, username, password, command "
                      "FROM events WHERE src_ip=? ORDER BY ts DESC LIMIT 25"),
    }


def stats(conn, p):
    clauses, vals = [], []
    frm, to = _ts(p.get("from")), _ts(p.get("to"))
    if frm is not None:
        clauses.append("ts >= ?"); vals.append(frm)
    if to is not None:
        clauses.append("ts <= ?"); vals.append(to)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

    def top(col, label="k", lim=15, extra=""):
        return [dict(r) for r in conn.execute(
            f"SELECT {col} {label}, COUNT(*) c FROM events{where} "
            f"{'AND' if where else 'WHERE'} {col} IS NOT NULL {extra} "
            f"GROUP BY {col} ORDER BY c DESC LIMIT {lim}", vals).fetchall()]

    tot = conn.execute(
        f"SELECT COUNT(*) n, COUNT(DISTINCT src_ip) ips FROM events{where}", vals).fetchone()
    return {
        "from": frm, "to": to, "total": tot["n"], "unique_ips": tot["ips"],
        "top_ips": top("src_ip"),
        "top_ports": top("dst_port"),
        "top_countries": top("country"),
        "by_type": [dict(r) for r in conn.execute(
            f"SELECT eventid k, COUNT(*) c FROM events{where} GROUP BY eventid ORDER BY c DESC", vals).fetchall()],
        "top_creds": [dict(r) for r in conn.execute(
            f"SELECT (COALESCE(username,'')||' / '||COALESCE(password,'')) k, COUNT(*) c FROM events{where} "
            f"{'AND' if where else 'WHERE'} username IS NOT NULL GROUP BY k ORDER BY c DESC LIMIT 15", vals).fetchall()],
    }


def search_malware(conn, p):
    limit = min(_int(p.get("limit"), 100) or 100, MAX_LIMIT)
    offset = max(_int(p.get("offset"), 0) or 0, 0)
    clauses, vals = [], []
    if p.get("sha256"):
        clauses.append("m.sha256 = ?"); vals.append(p["sha256"])
    if p.get("malicious") in ("1", "true", "yes", "on"):
        clauses.append("m.malicious = 1")
    fts = _fts_query(p.get("q"))
    if fts:
        base = ("FROM search_fts JOIN malware_samples m ON m.sha256 = search_fts.ref "
                "WHERE search_fts.kind='malware' AND search_fts MATCH ?")
        params = [fts]
    else:
        base = "FROM malware_samples m WHERE 1=1"
        params = []
    if clauses:
        base += "".join(" AND " + c for c in clauses)
        params += vals
    total = conn.execute("SELECT COUNT(*) " + base, params).fetchone()[0]
    rows = conn.execute("SELECT m.* " + base + " ORDER BY m.last_seen DESC LIMIT ? OFFSET ?",
                        params + [limit, offset]).fetchall()
    return {"total": total, "limit": limit, "offset": offset, "rows": [dict(r) for r in rows]}


# ---------------------------------------------------------------- http
class Handler(BaseHTTPRequestHandler):
    server_version = "honeyradar-api"

    def _send(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        p = {k: v[0] for k, v in parse_qs(u.query).items()}
        try:
            conn = _connect()
            try:
                if u.path == "/api/search":
                    self._send(search_events(conn, p))
                elif u.path == "/api/profile":
                    self._send(profile(conn, p.get("ip")))
                elif u.path == "/api/stats":
                    self._send(stats(conn, p))
                elif u.path == "/api/malware":
                    self._send(search_malware(conn, p))
                elif u.path in ("/api/health", "/api", "/"):
                    n = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                    m = conn.execute("SELECT COUNT(*) FROM malware_samples").fetchone()[0]
                    self._send({"ok": True, "events": n, "malware_samples": m,
                                "endpoints": ["/api/search", "/api/profile", "/api/stats", "/api/malware"]})
                else:
                    self._send({"error": "not found"}, 404)
            finally:
                conn.close()
        except Exception as exc:  # noqa: BLE001
            self._send({"error": str(exc)}, 500)

    def log_message(self, *args):
        pass  # quiet


def main():
    httpd = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"HoneyRadar query API on http://{BIND}:{PORT}  (db={DB_PATH})", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
