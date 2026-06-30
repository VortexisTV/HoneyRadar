"""
honeyradar_store.py - SQLite + FTS5 persistence for the HoneyRadar bridge.

Drop this next to cowrie_ws.py and, in the bridge, persist every NORMALISED
event right before you broadcast it:

    from honeyradar_store import HoneyRadarStore
    store = HoneyRadarStore("/opt/honeyradar/honeyradar.db")   # once, at startup
    ...
    store.record(normalized)        # then:  await broadcast(json.dumps(normalized))

record() routes honeyradar.malware.sample / source=="malware_scanner" events to
the malware_samples table and everything else to the events table. It NEVER
raises - a DB hiccup must never interrupt the live WebSocket stream.

Zero third-party dependencies (sqlite3 + json are stdlib). FTS5 ships with the
stock SQLite in CPython. Writer uses WAL so the read-only API can query
concurrently.
"""

import json
import os
import sqlite3
import time
from datetime import datetime, timezone

DEFAULT_DB = "/opt/honeyradar/honeyradar.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          INTEGER NOT NULL,          -- event time, epoch ms (UTC)
  received_at INTEGER NOT NULL,          -- insert time, epoch ms
  source      TEXT,                      -- cowrie | opencanary | suricata | wazuh | ...
  eventid     TEXT,
  src_ip      TEXT, src_port INTEGER,
  dst_ip      TEXT, dst_port INTEGER,
  protocol    TEXT,
  username    TEXT, password TEXT, command TEXT,
  country     TEXT, cc TEXT, city TEXT, asn TEXT, isp TEXT,
  sensor      TEXT,
  malicious   INTEGER DEFAULT 0,
  rep_score   INTEGER,
  actor       TEXT, malware TEXT,
  raw_json    TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src     ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_eid     ON events(eventid);
CREATE INDEX IF NOT EXISTS idx_events_src_ts  ON events(src_ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_mal     ON events(malicious);
CREATE INDEX IF NOT EXISTS idx_events_country ON events(country);
CREATE INDEX IF NOT EXISTS idx_events_dport   ON events(dst_port);
CREATE INDEX IF NOT EXISTS idx_events_source  ON events(source);

CREATE TABLE IF NOT EXISTS malware_samples (
  sha256     TEXT PRIMARY KEY,
  md5        TEXT, sha1 TEXT,
  first_seen INTEGER, last_seen INTEGER, hits INTEGER DEFAULT 1,
  filename   TEXT, size INTEGER,
  score      INTEGER, malicious INTEGER DEFAULT 0,
  malware    TEXT,
  clamav_infected INTEGER, clamav_sig TEXT,
  yara       TEXT,
  vt_malicious INTEGER, vt_total INTEGER, vt_type TEXT, vt_popular TEXT,
  mb_found   INTEGER, mb_tags TEXT,
  raw_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_mw_last  ON malware_samples(last_seen);
CREATE INDEX IF NOT EXISTS idx_mw_mal   ON malware_samples(malicious);
CREATE INDEX IF NOT EXISTS idx_mw_score ON malware_samples(score);

-- One shared full-text index. kind/ref are stored but not tokenised.
CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(
  raw_json, src_ip, username, password, command, country, eventid, malware, sha256,
  kind UNINDEXED, ref UNINDEXED,
  tokenize = 'unicode61 remove_diacritics 2'
);
"""


def _parse_ts(value):
    """Best-effort parse of Cowrie/OpenCanary timestamps -> epoch ms (UTC)."""
    if not value:
        return None
    s = str(value).strip().replace("T", " ").replace("Z", "")
    if "+" in s:
        s = s.split("+", 1)[0].strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except ValueError:
            continue
    return None


def _pick(d, *keys):
    for k in keys:
        if isinstance(d, dict):
            v = d.get(k)
            if v not in (None, ""):
                return v
    return None


def _to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


class HoneyRadarStore:
    def __init__(self, path=DEFAULT_DB):
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA busy_timeout=4000")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # -- public ------------------------------------------------------------
    def record(self, event):
        """Persist one normalised event. Never raises."""
        try:
            if not isinstance(event, dict):
                return
            src = str(event.get("source") or "").lower()
            eid = str(event.get("eventid") or "")
            if eid == "honeyradar.malware.sample" or src == "malware_scanner":
                self._insert_malware(event)
            else:
                self._insert_event(event)
        except Exception as exc:  # noqa: BLE001 - must not break the stream
            try:
                print(f"[honeyradar_store] insert error: {exc}", flush=True)
            except Exception:
                pass

    def close(self):
        try:
            self.conn.commit()
            self.conn.close()
        except Exception:
            pass

    # -- internals ---------------------------------------------------------
    def _insert_event(self, e):
        geo = e.get("geoip") if isinstance(e.get("geoip"), dict) else {}
        rep = e.get("reputation") if isinstance(e.get("reputation"), dict) else {}
        now = int(time.time() * 1000)
        ts = _parse_ts(_pick(e, "timestamp", "utc_time", "local_time")) or now

        src_ip = _pick(e, "src_ip", "srcIp", "src_host", "source_ip") or \
            _pick(e.get("data", {}) if isinstance(e.get("data"), dict) else {}, "srcip", "src_ip")
        dst_ip = _pick(e, "dst_ip", "dstIp", "dst_host", "dest_ip", "server_public_ip")
        country = _pick(geo, "country_name", "country") or _pick(e, "country")
        cc = _pick(geo, "country_code2", "country_code", "cc") or _pick(e, "cc")
        city = _pick(geo, "city") or _pick(e, "city")
        malicious = 1 if (rep.get("malicious") or e.get("malicious")) else 0

        row = (
            ts, now,
            (str(e.get("source")) if e.get("source") else _src_from_eventid(e.get("eventid"))),
            e.get("eventid"),
            src_ip, _to_int(_pick(e, "src_port", "srcPort")),
            dst_ip, _to_int(_pick(e, "dst_port", "dstPort", "dest_port")),
            _pick(e, "protocol", "proto"),
            _pick(e, "username", "user"), _pick(e, "password", "pass"),
            _pick(e, "input", "command"),
            country, (str(cc).upper() if cc else None), city,
            _pick(geo, "asn") or _pick(e, "asn"), _pick(geo, "isp", "org") or _pick(e, "isp"),
            _pick(e, "sensor", "node_id"),
            malicious,
            _to_int(rep.get("score")),
            rep.get("actor"), rep.get("malware"),
            json.dumps(e, separators=(",", ":"), ensure_ascii=False),
        )
        cur = self.conn.execute(
            """INSERT INTO events
               (ts, received_at, source, eventid, src_ip, src_port, dst_ip, dst_port,
                protocol, username, password, command, country, cc, city, asn, isp,
                sensor, malicious, rep_score, actor, malware, raw_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            row,
        )
        self.conn.execute(
            """INSERT INTO search_fts
               (rowid, raw_json, src_ip, username, password, command, country, eventid, malware, sha256, kind, ref)
               VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?)""",
            (row[22], src_ip or "", row[9] or "", row[10] or "", row[11] or "",
             country or "", e.get("eventid") or "", "", "", "event", cur.lastrowid),
        )
        self.conn.commit()

    def _insert_malware(self, e):
        h = e.get("hashes") if isinstance(e.get("hashes"), dict) else {}
        sha256 = _pick(e, "sha256") or _pick(h, "sha256")
        if not sha256:
            return
        vt = e.get("virustotal") if isinstance(e.get("virustotal"), dict) else {}
        cl = e.get("clamav") if isinstance(e.get("clamav"), dict) else {}
        ya = e.get("yara") if isinstance(e.get("yara"), dict) else {}
        mb = e.get("malwarebazaar") if isinstance(e.get("malwarebazaar"), dict) else {}
        now = int(time.time() * 1000)
        ts = _parse_ts(e.get("timestamp")) or now
        vt_total = None
        if vt:
            vt_total = (_to_int(vt.get("malicious")) or 0) + (_to_int(vt.get("suspicious")) or 0) + \
                       (_to_int(vt.get("harmless")) or 0) + (_to_int(vt.get("undetected")) or 0)
        yara_matches = "/".join(ya.get("matches") or []) if isinstance(ya.get("matches"), list) else None
        mb_tags = ", ".join(mb.get("tags") or []) if isinstance(mb.get("tags"), list) else None

        self.conn.execute(
            """INSERT INTO malware_samples
               (sha256, md5, sha1, first_seen, last_seen, hits, filename, size, score, malicious,
                malware, clamav_infected, clamav_sig, yara, vt_malicious, vt_total, vt_type, vt_popular,
                mb_found, mb_tags, raw_json)
               VALUES (?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(sha256) DO UPDATE SET
                 last_seen=excluded.last_seen, hits=malware_samples.hits+1,
                 score=excluded.score, malicious=excluded.malicious, malware=excluded.malware,
                 clamav_infected=excluded.clamav_infected, clamav_sig=excluded.clamav_sig,
                 yara=excluded.yara, vt_malicious=excluded.vt_malicious, vt_total=excluded.vt_total,
                 vt_type=excluded.vt_type, vt_popular=excluded.vt_popular,
                 mb_found=excluded.mb_found, mb_tags=excluded.mb_tags, raw_json=excluded.raw_json""",
            (sha256, _pick(h, "md5"), _pick(h, "sha1"), ts, ts,
             e.get("filename"), _to_int(e.get("size")), _to_int(e.get("score")),
             1 if e.get("malicious") else 0, e.get("malware"),
             1 if cl.get("infected") else 0, cl.get("signature"),
             yara_matches, _to_int(vt.get("malicious")), vt_total,
             vt.get("type_description"), vt.get("popular_threat_name"),
             1 if mb.get("found") else 0, mb_tags,
             json.dumps(e, separators=(",", ":"), ensure_ascii=False)),
        )
        # keep one FTS row per sha256
        self.conn.execute("DELETE FROM search_fts WHERE kind='malware' AND ref=?", (sha256,))
        self.conn.execute(
            """INSERT INTO search_fts
               (rowid, raw_json, src_ip, username, password, command, country, eventid, malware, sha256, kind, ref)
               VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?)""",
            (json.dumps(e, separators=(",", ":"), ensure_ascii=False), "", "", "", "", "",
             "honeyradar.malware.sample", e.get("malware") or "", sha256, "malware", sha256),
        )
        self.conn.commit()


def _src_from_eventid(eventid):
    if not eventid:
        return None
    eid = str(eventid)
    if eid.startswith("cowrie."):
        return "cowrie"
    if eid.startswith("opencanary."):
        return "opencanary"
    if eid.startswith("honeyradar.malware"):
        return "malware_scanner"
    return None
